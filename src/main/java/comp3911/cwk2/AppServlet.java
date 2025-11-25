package comp3911.cwk2;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

    private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
    private static final String AUTH_QUERY = "select * from user where username=? and password=?";
    private static final String SEARCH_QUERY = "select * from patient where surname=? collate nocase";

    // replace with env
    private static final String TURNSTIL_SITE_KEY = "0x4AAAAAACCRXf3o8M8po2RJ";
    private static final String TURNSTIL_SECRET = "0x4AAAAAACCRXe5U1DAs4TToAY-MBO-zN6w";

    private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
    private Connection database;

    @Override
    public void init() throws ServletException {
        configureTemplateEngine();
        connectToDatabase();
    }

    private void configureTemplateEngine() throws ServletException {
        try {
            fm.setDirectoryForTemplateLoading(new File("./templates"));
            fm.setOutputFormat(freemarker.core.HTMLOutputFormat.INSTANCE);
            fm.setDefaultEncoding("UTF-8");
            fm.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
            fm.setLogTemplateExceptions(false);
            fm.setWrapUncheckedExceptions(true);
        } catch (IOException error) {
            throw new ServletException(error.getMessage());
        }
    }

    private void connectToDatabase() throws ServletException {
        try {
            database = DriverManager.getConnection(CONNECTION_URL);
        } catch (SQLException error) {
            throw new ServletException(error.getMessage());
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            Map<String, Object> model = new HashMap<>();
            model.put("turnstileSiteKey", TURNSTIL_SITE_KEY);
            Template template = fm.getTemplate("login.html");
            template.process(model, response.getWriter());
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (TemplateException error) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    protected boolean validateTurnstile(String token, String remoteIp) {
        try {
            URL url = new URL("https://challenges.cloudflare.com/turnstile/v0/siteverify");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            String postData = "secret=" + URLEncoder.encode(TURNSTIL_SECRET, "UTF-8")
                    + "&response=" + URLEncoder.encode(token, "UTF-8")
                    + "&remoteip=" + URLEncoder.encode(remoteIp, "UTF-8");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData.getBytes(StandardCharsets.UTF_8));
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }

            // Parse JSON response
            JSONObject json = new JSONObject(sb.toString());
            return json.getBoolean("success");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Get form parameters
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String surname = request.getParameter("surname");
        String turnstileToken = request.getParameter("cf-turnstile-response");

        if (!validateTurnstile(turnstileToken, request.getRemoteAddr())) {
            try {
                Template template = fm.getTemplate("invalid.html");
                template.process(null, response.getWriter());
                response.setContentType("text/html");
                response.setStatus(HttpServletResponse.SC_OK);

            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        try {
            if (authenticated(username, password)) {
                // Get search results and merge with template
                Map<String, Object> model = new HashMap<>();
                // FIX for Flaw #5 (Broken Access Control): enforce doctor-patient relationship
                String doctorId = getDoctorIdForUser(username);

                model.put("records", searchResults(surname, doctorId));

                Template template = fm.getTemplate("details.html");
                template.process(model, response.getWriter());
            } else {
                Template template = fm.getTemplate("invalid.html");
                template.process(null, response.getWriter());
            }
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (Exception error) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private boolean authenticated(String username, String password) throws SQLException {
        try (PreparedStatement stmt = database.prepareStatement(AUTH_QUERY)) {
            stmt.setString(1, username);
            stmt.setString(2, password);

            ResultSet results = stmt.executeQuery();
            return results.next();
        }
    }
// FIX for Flaw #5 (Broken Access Control): retrieve doctorId for logged-in user
private String getDoctorIdForUser(String username) throws SQLException {
    String query = "SELECT doctorId FROM user WHERE username = ?";

    try (PreparedStatement stmt = database.prepareStatement(query)) {
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();

        if (rs.next()) {
            return rs.getString("doctorId");
        }
    }
    return null;
}

    // FIX for Flaw #5 (Broken Access Control): restrict results to patients of this doctor
private List<Record> searchResults(String surname, String doctorId) throws SQLException {

    String query = "SELECT * FROM patient WHERE surname=? COLLATE NOCASE AND doctorId=?";

    List<Record> records = new ArrayList<>();

    try (PreparedStatement stmt = database.prepareStatement(query)) {
        stmt.setString(1, surname);
        stmt.setString(2, doctorId);

        ResultSet results = stmt.executeQuery();

        while (results.next()) {
            Record rec = new Record();
            rec.setSurname(results.getString("surname"));
            rec.setForename(results.getString("forename"));
            rec.setAddress(results.getString("address"));
            rec.setDateOfBirth(results.getString("dateOfBirth"));
            rec.setDoctorId(results.getString("doctorId"));
            rec.setDiagnosis(results.getString("diagnosis"));
            records.add(rec);
        }
    }
    return records;
}

}
