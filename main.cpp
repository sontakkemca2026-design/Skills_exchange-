#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mysql.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <algorithm>

#include "db_config.h"

#pragma comment(lib, "ws2_32.lib")

const size_t MAX_REQUEST_SIZE = 2 * 1024 * 1024;

// ==================================================
// READ HTML FILE
// ==================================================

std::string readFile(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);

    if (!file)
        return "";

    std::ostringstream output;
    output << file.rdbuf();

    return output.str();
}

// ==================================================
// URL DECODE
// ==================================================

std::string decode(const std::string& value)
{
    std::string result;

    for (size_t i = 0; i < value.size(); i++)
    {
        if (value[i] == '+')
        {
            result += ' ';
        }
        else if (value[i] == '%' && i + 2 < value.size())
        {
            char hex[3] = {
                value[i + 1],
                value[i + 2],
                '\0'
            };

            char* end = nullptr;
            long number = std::strtol(hex, &end, 16);

            if (end != hex && *end == '\0')
            {
                result += static_cast<char>(number);
                i += 2;
            }
            else
            {
                result += value[i];
            }
        }
        else
        {
            result += value[i];
        }
    }

    return result;
}

// ==================================================
// PARSE FORM DATA
// ==================================================

std::map<std::string, std::string> parseForm(
    const std::string& body)
{
    std::map<std::string, std::string> fields;
    std::istringstream input(body);
    std::string pair;

    while (std::getline(input, pair, '&'))
    {
        size_t position = pair.find('=');

        if (position == std::string::npos)
            continue;

        std::string key = decode(pair.substr(0, position));
        std::string value = decode(pair.substr(position + 1));

        fields[key] = value;
    }

    return fields;
}

// ==================================================
// JSON ESCAPE
// ==================================================

std::string jsonEscape(const std::string& value)
{
    std::string result;

    for (unsigned char c : value)
    {
        switch (c)
        {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;

            default:
                if (c < 32)
                {
                    char buffer[7];
                    std::snprintf(
                        buffer,
                        sizeof(buffer),
                        "\\u%04x",
                        c
                    );
                    result += buffer;
                }
                else
                {
                    result += static_cast<char>(c);
                }
        }
    }

    return result;
}

// ==================================================
// SEND HTTP RESPONSE
// ==================================================

void respond(
    SOCKET client,
    int status,
    const std::string& contentType,
    const std::string& body)
{
    std::string statusText;

    switch (status)
    {
        case 200: statusText = "OK"; break;
        case 400: statusText = "Bad Request"; break;
        case 401: statusText = "Unauthorized"; break;
        case 404: statusText = "Not Found"; break;
        case 405: statusText = "Method Not Allowed"; break;
        case 409: statusText = "Conflict"; break;
        case 413: statusText = "Payload Too Large"; break;
        default: statusText = "Internal Server Error"; break;
    }

    std::string response =
        "HTTP/1.1 " + std::to_string(status) + " " + statusText + "\r\n" +
        "Content-Type: " + contentType + "; charset=utf-8\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Cache-Control: no-store\r\n" +
        "X-Content-Type-Options: nosniff\r\n" +
        "Connection: close\r\n\r\n" +
        body;

    size_t sent = 0;

    while (sent < response.size())
    {
        int count = send(
            client,
            response.data() + sent,
            static_cast<int>(response.size() - sent),
            0
        );

        if (count == SOCKET_ERROR || count == 0)
            break;

        sent += static_cast<size_t>(count);
    }
}

// ==================================================
// DATABASE CONNECTION
// ==================================================

MYSQL* connectDB()
{
    MYSQL* db = mysql_init(nullptr);

    if (db == nullptr)
    {
        std::cerr << "MySQL initialization failed.\n";
        return nullptr;
    }

    my_bool sslEnforce = 0;
    my_bool sslVerify = 0;

    mysql_options(db, MYSQL_OPT_SSL_ENFORCE, &sslEnforce);
    mysql_options(db, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &sslVerify);

    if (mysql_real_connect(
        db,
        DB_HOST,
        DB_USER,
        DB_PASSWORD,
        DB_NAME,
        DB_PORT,
        nullptr,
        0) == nullptr)
    {
        std::cerr << "Database connection failed: "
                  << mysql_error(db) << '\n';

        mysql_close(db);
        return nullptr;
    }

    if (mysql_set_character_set(db, "utf8mb4") != 0)
    {
        std::cerr << "Character set error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);
        return nullptr;
    }

    return db;
}

// ==================================================
// ESCAPE SQL VALUES
// ==================================================

std::string escaped(MYSQL* db, const std::string& value)
{
    std::string result(value.size() * 2 + 1, '\0');

    unsigned long length = mysql_real_escape_string(
        db,
        result.data(),
        value.c_str(),
        static_cast<unsigned long>(value.size())
    );

    result.resize(length);
    return result;
}

// ==================================================
// CHECK NUMERIC ID
// ==================================================

bool isNumericId(const std::string& value)
{
    return !value.empty() &&
        value.size() <= 10 &&
        std::all_of(
            value.begin(),
            value.end(),
            [](unsigned char c)
            {
                return std::isdigit(c);
            }
        );
}

// ==================================================
// REGISTRATION API
// POST /api/register
// ==================================================

void handleRegister(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    const char* requiredFields[] = {
        "username", "email", "passwordHash",
        "course", "mobile", "college"
    };

    for (const char* key : requiredFields)
    {
        if (!fields.count(key) || fields.at(key).empty())
        {
            respond(client, 400, "application/json",
                R"({"success":false,"message":"Please fill in all fields."})");
            return;
        }
    }

    if (fields.at("passwordHash").size() != 64)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid password data."})");
        return;
    }

    if (fields.at("username").size() > 100 ||
        fields.at("email").size() > 150 ||
        fields.at("course").size() > 100 ||
        fields.at("mobile").size() > 30 ||
        fields.at("college").size() > 150)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"One or more fields are too long."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    std::string username = escaped(db, fields.at("username"));
    std::string email = escaped(db, fields.at("email"));
    std::string passwordHash = escaped(db, fields.at("passwordHash"));
    std::string course = escaped(db, fields.at("course"));
    std::string mobile = escaped(db, fields.at("mobile"));
    std::string college = escaped(db, fields.at("college"));

    const std::string sql =
        "INSERT INTO users "
        "(username, full_name, email, course, password_hash, mobile, college, role) "
        "VALUES ('" + username + "', '" + username + "', '" +
        email + "', '" + course + "', '" + passwordHash +
        "', '" + mobile + "', '" + college + "', 'student')";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        unsigned int errorCode = mysql_errno(db);

        std::cerr << "Registration SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        if (errorCode == 1062)
        {
            respond(client, 409, "application/json",
                R"({"success":false,"message":"Username or email is already registered."})");
        }
        else
        {
            respond(client, 500, "application/json",
                R"({"success":false,"message":"Registration failed. Check users table columns."})");
        }

        return;
    }

    mysql_close(db);

    respond(client, 200, "application/json",
        R"({"success":true,"message":"Registration successful! Please log in."})");
}

// ==================================================
// LOGIN API
// POST /api/login
// ==================================================

void handleLogin(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    if (!fields.count("username") ||
        !fields.count("passwordHash") ||
        fields.at("username").empty() ||
        fields.at("passwordHash").empty())
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Enter username and password."})");
        return;
    }

    if (fields.at("passwordHash").size() != 64)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid password data."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    std::string username = escaped(db, fields.at("username"));
    std::string passwordHash = escaped(db, fields.at("passwordHash"));

    const std::string sql =
        "SELECT user_id, full_name FROM users "
        "WHERE username='" + username +
        "' AND password_hash='" + passwordHash +
        "' AND role='student' LIMIT 1";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Login SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Login query failed. Check users table columns."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read login result."})");
        return;
    }

    MYSQL_ROW row = mysql_fetch_row(result);

    if (!row)
    {
        mysql_free_result(result);
        mysql_close(db);

        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid username or password. Register first if you do not have an account."})");
        return;
    }

    std::string userId = row[0] ? row[0] : "0";
    std::string fullName = row[1] ? row[1] : "Student";

    mysql_free_result(result);
    mysql_close(db);

    respond(client, 200, "application/json",
        "{\"success\":true,\"message\":\"Login successful!\",\"full_name\":\"" +
        jsonEscape(fullName) + "\",\"user_id\":" + userId + "}");
}

// ==================================================
// ADMIN LOGIN API
// POST /api/admin/login
// ==================================================

void handleAdminLogin(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    if (!fields.count("username") ||
        !fields.count("password") ||
        fields.at("username").empty() ||
        fields.at("password").empty())
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Enter admin username and password."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    std::string username = escaped(db, fields.at("username"));
    std::string password = escaped(db, fields.at("password"));

    const std::string sql =
        "SELECT admin_id FROM admins "
        "WHERE username='" + username +
        "' AND password_hash=SHA2('" + password +
        "', 256) LIMIT 1";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Admin login SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Admin login query failed. Check admins table."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read admin login result."})");
        return;
    }

    MYSQL_ROW row = mysql_fetch_row(result);

    if (!row)
    {
        mysql_free_result(result);
        mysql_close(db);

        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid admin username or password."})");
        return;
    }

    std::string adminId = row[0] ? row[0] : "0";

    mysql_free_result(result);
    mysql_close(db);

    respond(client, 200, "application/json",
        "{\"success\":true,\"message\":\"Admin login successful!\",\"adminId\":" +
        adminId + "}");
}

// ==================================================
// ADD SKILL API
// POST /api/skills
// ==================================================

void handleAddSkill(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    const char* requiredFields[] = {
        "userId", "skillName", "category",
        "level", "availability", "description"
    };

    for (const char* key : requiredFields)
    {
        if (!fields.count(key) || fields.at(key).empty())
        {
            respond(client, 400, "application/json",
                R"({"success":false,"message":"Please fill in all required fields."})");
            return;
        }
    }

    const std::string userId = fields.at("userId");
    const std::string skillName = fields.at("skillName");
    const std::string category = fields.at("category");
    const std::string level = fields.at("level");
    const std::string availability = fields.at("availability");
    const std::string description = fields.at("description");

    const std::string experience =
        fields.count("experience") ? fields.at("experience") : "";

    if (!isNumericId(userId))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid student ID. Please log in again."})");
        return;
    }

    if (skillName.size() > 100 ||
        category.size() > 100 ||
        level.size() > 30 ||
        experience.size() > 50 ||
        availability.size() > 30)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"One or more fields are too long."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string checkSql =
        "SELECT user_id FROM users WHERE user_id=" +
        userId + " AND role='student' LIMIT 1";

    if (mysql_query(db, checkSql.c_str()) != 0)
    {
        std::cerr << mysql_error(db) << '\n';
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify student account."})");
        return;
    }

    MYSQL_RES* checkResult = mysql_store_result(db);
    MYSQL_ROW studentRow = checkResult ?
        mysql_fetch_row(checkResult) : nullptr;

    if (!studentRow)
    {
        if (checkResult) mysql_free_result(checkResult);
        mysql_close(db);

        respond(client, 401, "application/json",
            R"({"success":false,"message":"Student account not found. Please log in again."})");
        return;
    }

    mysql_free_result(checkResult);

    std::string safeName = escaped(db, skillName);
    std::string safeCategory = escaped(db, category);
    std::string safeLevel = escaped(db, level);
    std::string safeAvailability = escaped(db, availability);
    std::string safeDescription = escaped(db, description);

    std::string safeExperience = experience.empty()
        ? "NULL"
        : "'" + escaped(db, experience) + "'";

    const std::string sql =
        "INSERT INTO skills "
        "(user_id, skill_name, skill_type, category, description, "
        "skill_level, experience, availability) "
        "VALUES (" + userId + ", '" + safeName +
        "', 'teach', '" + safeCategory +
        "', '" + safeDescription + "', '" + safeLevel +
        "', " + safeExperience + ", '" + safeAvailability + "')";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Add Skill SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not save skill. Check the skills table structure."})");
        return;
    }

    mysql_close(db);

    respond(client, 200, "application/json",
        R"({"success":true,"message":"Your skill has been saved successfully!"})");
}

// ==================================================
// EXPLORE SKILLS API
// GET /api/skills?userId=ID
// ==================================================


void handleExploreSkills(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("userId") ||
        !isNumericId(params.at("userId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please log in again."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string userId = params.at("userId");

    const std::string sql =
        "SELECT s.skill_id, s.user_id, s.skill_name, s.category, "
        "s.description, s.skill_level, s.experience, s.availability, "
        "u.full_name, u.profile_photo "
        "FROM skills s "
        "INNER JOIN users u ON u.user_id=s.user_id "
        "WHERE s.skill_type='teach' AND s.user_id<>" + userId +
        " ORDER BY s.created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Explore skills SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load skills."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read skills."})");
        return;
    }

    std::ostringstream json;
    json << R"({"success":true,"skills":[)";

    bool first = true;
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        if (!first) json << ',';
        first = false;

        auto value = [&row](unsigned int i) -> std::string
        {
            return row[i] ? row[i] : "";
        };

        json << "{"
             << R"("skill_id":)" << value(0) << ','
             << R"("user_id":)" << value(1) << ','
             << R"("skill_name":")" << jsonEscape(value(2)) << "\","
             << R"("category":")" << jsonEscape(value(3)) << "\","
             << R"("description":")" << jsonEscape(value(4)) << "\","
             << R"("skill_level":")" << jsonEscape(value(5)) << "\","
             << R"("experience":")" << jsonEscape(value(6)) << "\","
             << R"("availability":")" << jsonEscape(value(7)) << "\","
             << R"("owner_name":")" << jsonEscape(value(8)) << "\","
             << R"("profile_photo":")" << jsonEscape(value(9)) << "\"}";
    }

    json << "]}";

    mysql_free_result(result);
    mysql_close(db);

    respond(client, 200, "application/json", json.str());
}


// ==================================================
// CREATE SKILL REQUEST API
// POST /api/requests
//
// Uses your actual table: exchange_requests
// ==================================================

void handleCreateRequest(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    if (!fields.count("skillId") ||
        !fields.count("requesterId") ||
        !fields.count("question") ||
        !isNumericId(fields.at("skillId")) ||
        !isNumericId(fields.at("requesterId")) ||
        fields.at("question").empty())
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please enter your question."})");
        return;
    }

    if (fields.at("question").size() > 3000)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Your question is too long."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string skillId = fields.at("skillId");
    const std::string requesterId = fields.at("requesterId");

    const std::string checkSql =
        "SELECT user_id FROM skills "
        "WHERE skill_id=" + skillId +
        " AND skill_type='teach' LIMIT 1";

    if (mysql_query(db, checkSql.c_str()) != 0)
    {
        std::cerr << mysql_error(db) << '\n';
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not check this skill."})");
        return;
    }

    MYSQL_RES* check = mysql_store_result(db);
    MYSQL_ROW row = check ? mysql_fetch_row(check) : nullptr;

    if (!row || !row[0])
    {
        if (check) mysql_free_result(check);
        mysql_close(db);

        respond(client, 404, "application/json",
            R"({"success":false,"message":"This skill is no longer available."})");
        return;
    }

    const std::string receiverId = row[0];

    mysql_free_result(check);

    if (receiverId == requesterId)
    {
        mysql_close(db);

        respond(client, 400, "application/json",
            R"({"success":false,"message":"You cannot request your own skill."})");
        return;
    }

    const std::string message =
        escaped(db, fields.at("question"));

    const std::string insertSql =
        "INSERT INTO exchange_requests "
        "(requester_id, receiver_id, skill_id, message) "
        "VALUES (" + requesterId + ", " +
        receiverId + ", " + skillId + ", '" +
        message + "')";

    if (mysql_query(db, insertSql.c_str()) != 0)
    {
        std::cerr << "Create request SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not send your request. Check exchange_requests columns."})");
        return;
    }

    mysql_close(db);

    respond(client, 200, "application/json",
        R"({"success":true,"message":"Your learning request was sent!"})");
}

// ==================================================
// VIEW SENT / RECEIVED REQUESTS API
// GET /api/requests?userId=ID&view=sent
// GET /api/requests?userId=ID&view=received
// ==================================================

void handleGetRequests(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("userId") ||
        !isNumericId(params.at("userId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please log in again."})");
        return;
    }

    const std::string userId = params.at("userId");
    const std::string view =
        params.count("view") ? params.at("view") : "sent";

    if (view != "sent" && view != "received")
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid request view."})");
        return;
    }

    const std::string whereColumn =
        (view == "received") ? "r.receiver_id" : "r.requester_id";

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string sql =
        "SELECT r.request_id, r.skill_id, "
        "r.requester_id, r.receiver_id, "
        "r.message, COALESCE(r.response_message,''), "
        "COALESCE(r.status,'pending'), "
        "DATE_FORMAT(r.created_at,'%d %b %Y %h:%i %p'), "
        "s.skill_name, requester.full_name, receiver.full_name "
        "FROM exchange_requests r "
        "INNER JOIN skills s ON s.skill_id=r.skill_id "
        "INNER JOIN users requester "
        "ON requester.user_id=r.requester_id "
        "INNER JOIN users receiver "
        "ON receiver.user_id=r.receiver_id "
        "WHERE " + whereColumn + "=" + userId +
        " ORDER BY r.created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Get requests SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load requests."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read requests."})");
        return;
    }

    std::ostringstream json;
    json << R"({"success":true,"requests":[)";

    bool first = true;
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        if (!first) json << ',';
        first = false;

        auto value = [&](unsigned int i) -> std::string
        {
            return row[i] ? row[i] : "";
        };

        json << "{"
             << R"("request_id":)" << value(0) << ','
             << R"("skill_id":)" << value(1) << ','
             << R"("requester_id":)" << value(2) << ','
             << R"("receiver_id":)" << value(3) << ','
             << R"("message":")" << jsonEscape(value(4)) << "\","
             << R"("question":")" << jsonEscape(value(4)) << "\","
             << R"("response_message":")" << jsonEscape(value(5)) << "\","
             << R"("reply":")" << jsonEscape(value(5)) << "\","
             << R"("status":")" << jsonEscape(value(6)) << "\","
             << R"("created_at":")" << jsonEscape(value(7)) << "\","
             << R"("skill_name":")" << jsonEscape(value(8)) << "\","
             << R"("requester_name":")" << jsonEscape(value(9)) << "\","
             << R"("receiver_name":")" << jsonEscape(value(10)) << "\","
             << R"("owner_name":")" << jsonEscape(value(10)) << "\"}";
    }

    json << "]}";

    mysql_free_result(result);
    mysql_close(db);

    respond(client, 200, "application/json", json.str());
}
// ==================================================
// STUDENT DASHBOARD API
// GET /api/dashboard?userId=ID
// ==================================================



void handleDashboard(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("userId") ||
        !isNumericId(params.at("userId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Student login information not found. Please log in again."})");
        return;
    }

    const std::string userId = params.at("userId");

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string sql =
        "SELECT "
        "u.full_name, "
        "(SELECT COUNT(*) FROM skills "
        " WHERE user_id=u.user_id AND skill_type='teach'), "
        "(SELECT COUNT(*) FROM skills "
        " WHERE user_id=u.user_id AND skill_type='learn'), "
        "(SELECT COUNT(*) FROM exchange_requests "
        " WHERE requester_id=u.user_id), "
        "(SELECT COUNT(*) FROM exchange_requests "
        " WHERE receiver_id=u.user_id), "
        "u.profile_photo "
        "FROM users u "
        "WHERE u.user_id=" + userId + " "
        "AND u.role='student' "
        "LIMIT 1";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Dashboard SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load dashboard information."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read dashboard information."})");
        return;
    }

    MYSQL_ROW row = mysql_fetch_row(result);

    if (!row)
    {
        mysql_free_result(result);
        mysql_close(db);

        respond(client, 404, "application/json",
            R"({"success":false,"message":"Student account not found. Please log in again."})");
        return;
    }

    std::string fullName = row[0] ? row[0] : "Student";
    std::string skillsShared = row[1] ? row[1] : "0";
    std::string skillsLearning = row[2] ? row[2] : "0";
    std::string requestsSent = row[3] ? row[3] : "0";
    std::string requestsReceived = row[4] ? row[4] : "0";

    // ADDED: GET STUDENT PROFILE PHOTO
    std::string profilePhoto = row[5] ? row[5] : "";

    mysql_free_result(result);
    mysql_close(db);

    std::ostringstream json;

    json << "{"
         << R"("success":true,)"
         << R"("full_name":")" << jsonEscape(fullName) << "\","
         << R"("profile_photo":")" << jsonEscape(profilePhoto) << "\","
         << R"("skills_shared":)" << skillsShared << ","
         << R"("skills_learning":)" << skillsLearning << ","
         << R"("requests_sent":)" << requestsSent << ","
         << R"("requests_received":)" << requestsReceived
         << "}";

    respond(client, 200, "application/json", json.str());
}


// ==================================================
// ADMIN DASHBOARD API
// GET /api/admin/dashboard?adminId=ID
// ==================================================

void handleAdminDashboard(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("adminId") ||
        !isNumericId(params.at("adminId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Admin login information not found."})");
        return;
    }

    const std::string adminId = params.at("adminId");

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    // Verify that this admin account exists.
    const std::string verifySql =
        "SELECT admin_id FROM admins WHERE admin_id=" +
        adminId + " LIMIT 1";

    if (mysql_query(db, verifySql.c_str()) != 0)
    {
        std::cerr << "Admin verification error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Admin verification failed."})");
        return;
    }

    MYSQL_RES* verifyResult = mysql_store_result(db);

    if (!verifyResult)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify admin."})");
        return;
    }

    MYSQL_ROW adminRow = mysql_fetch_row(verifyResult);

    if (!adminRow)
    {
        mysql_free_result(verifyResult);
        mysql_close(db);

        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid admin account."})");
        return;
    }

    mysql_free_result(verifyResult);

    // Get dashboard statistics.
    const std::string sql =
        "SELECT "
        "(SELECT COUNT(*) FROM users WHERE role='student'), "
        "(SELECT COUNT(*) FROM skills), "
        "(SELECT COUNT(*) FROM exchange_requests), "
        "(SELECT COUNT(*) FROM exchange_requests "
        " WHERE LOWER(status)='completed')";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Admin dashboard SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load admin dashboard."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read dashboard statistics."})");
        return;
    }

    MYSQL_ROW row = mysql_fetch_row(result);

    if (!row)
    {
        mysql_free_result(result);
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Dashboard statistics are unavailable."})");
        return;
    }

    std::string totalStudents = row[0] ? row[0] : "0";
    std::string totalSkills = row[1] ? row[1] : "0";
    std::string totalRequests = row[2] ? row[2] : "0";
    std::string completedExchanges = row[3] ? row[3] : "0";

    mysql_free_result(result);
    mysql_close(db);

    std::ostringstream json;

    json << "{"
         << R"("success":true,)"
         << R"("totalStudents":)" << totalStudents << ","
         << R"("totalSkills":)" << totalSkills << ","
         << R"("totalRequests":)" << totalRequests << ","
         << R"("completedExchanges":)" << completedExchanges
         << "}";

    respond(client, 200, "application/json", json.str());
}

// ==================================================
// REPLY TO REQUEST API
// POST /api/reply
//
// Uses response_message from your actual table.
// ==================================================

void handleReply(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    if (!fields.count("requestId") ||
        !fields.count("ownerId") ||
        !fields.count("reply") ||
        !isNumericId(fields.at("requestId")) ||
        !isNumericId(fields.at("ownerId")) ||
        fields.at("reply").empty())
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please write a reply."})");
        return;
    }

    if (fields.at("reply").size() > 3000)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Your reply is too long."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string requestId = fields.at("requestId");
    const std::string ownerId = fields.at("ownerId");

    const std::string reply =
        escaped(db, fields.at("reply"));

    const std::string updateSql =
        "UPDATE exchange_requests "
        "SET response_message='" + reply +
        "' WHERE request_id=" + requestId +
        " AND receiver_id=" + ownerId;

    if (mysql_query(db, updateSql.c_str()) != 0)
    {
        std::cerr << "Reply SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not save your reply."})");
        return;
    }

    const bool updated = mysql_affected_rows(db) > 0;

    mysql_close(db);

    if (!updated)
    {
        respond(client, 404, "application/json",
            R"({"success":false,"message":"Request not found for this student."})");
        return;
    }

    respond(client, 200, "application/json",
        R"({"success":true,"message":"Your reply was sent to the student."})");
}

// ==================================================
// READ HTTP REQUEST
// ==================================================

bool readRequest(SOCKET client, std::string& request)
{
    char buffer[4096];
    size_t contentLength = 0;

    while (true)
    {
        int received = recv(
            client,
            buffer,
            sizeof(buffer),
            0
        );

        if (received <= 0)
            return false;

        request.append(buffer, static_cast<size_t>(received));

        if (request.size() > MAX_REQUEST_SIZE)
            return false;

        size_t headerEnd = request.find("\r\n\r\n");

        if (headerEnd == std::string::npos)
            continue;

        std::istringstream headers(request.substr(0, headerEnd));
        std::string line;

        // Skip request line.
        std::getline(headers, line);

        while (std::getline(headers, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            std::string lower = line;

            std::transform(
                lower.begin(),
                lower.end(),
                lower.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(std::tolower(c));
                }
            );

            if (lower.rfind("content-length:", 0) == 0)
            {
                try
                {
                    contentLength = static_cast<size_t>(
                        std::stoull(
                            line.substr(line.find(':') + 1)
                        )
                    );
                }
                catch (...)
                {
                    return false;
                }

                if (contentLength > MAX_REQUEST_SIZE)
                    return false;
            }
        }

        size_t bodyStart = headerEnd + 4;

        if (request.size() >= bodyStart + contentLength)
            return true;
    }
}

// ==================================================
// GET STUDENT PROFILE API
// GET /api/profile?userId=ID
// ==================================================

void handleGetProfile(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("userId") || !isNumericId(params.at("userId"))) {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please log in again."})");
        return;
    }

    std::string userId = params.at("userId");
    MYSQL* db = connectDB();

    if (!db) {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    std::string sql =
        "SELECT full_name, email, course, "
        "COALESCE(mobile,''), COALESCE(college,''), "
        "COALESCE(profile_photo,'') "
        "FROM users WHERE user_id=" + userId +
        " AND role='student' LIMIT 1";

    if (mysql_query(db, sql.c_str()) != 0) {
        std::cerr << "Profile SQL error: " << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load profile."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);
    MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;

    if (!row) {
        if (result) mysql_free_result(result);
        mysql_close(db);
        respond(client, 404, "application/json",
            R"({"success":false,"message":"Student account not found."})");
        return;
    }

    auto value = [&](unsigned int i) -> std::string {
        return row[i] ? row[i] : "";
    };

    std::string fullName = value(0);
    std::string email = value(1);
    std::string course = value(2);
    std::string mobile = value(3);
    std::string college = value(4);
    std::string photo = value(5);

    mysql_free_result(result);

    std::ostringstream json;
    json << "{\"success\":true,"
         << "\"full_name\":\"" << jsonEscape(fullName) << "\","
         << "\"email\":\"" << jsonEscape(email) << "\","
         << "\"course\":\"" << jsonEscape(course) << "\","
         << "\"mobile\":\"" << jsonEscape(mobile) << "\","
         << "\"college\":\"" << jsonEscape(college) << "\","
         << "\"profile_photo\":\"" << jsonEscape(photo) << "\","
         << "\"skills\":[";

    std::string skillSql =
        "SELECT skill_name, category, skill_level "
        "FROM skills WHERE user_id=" + userId +
        " AND skill_type='teach' ORDER BY created_at DESC";

    if (mysql_query(db, skillSql.c_str()) != 0) {
        std::cerr << "Profile skills SQL error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load offered skills."})");
        return;
    }

    MYSQL_RES* skillResult = mysql_store_result(db);
    if (!skillResult) {
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read offered skills."})");
        return;
    }

    bool first = true;
    MYSQL_ROW skillRow;

    while ((skillRow = mysql_fetch_row(skillResult)) != nullptr) {
        if (!first) json << ',';
        first = false;

        json << "{\"skill_name\":\""
             << jsonEscape(skillRow[0] ? skillRow[0] : "")
             << "\",\"category\":\""
             << jsonEscape(skillRow[1] ? skillRow[1] : "")
             << "\",\"level\":\""
             << jsonEscape(skillRow[2] ? skillRow[2] : "")
             << "\"}";
    }

    json << "]}";

    mysql_free_result(skillResult);
    mysql_close(db);

    respond(client, 200, "application/json", json.str());
}


// ==================================================
// UPDATE STUDENT PROFILE API
// POST /api/profile/update
// ==================================================

void handleUpdateProfile(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    const char* required[] = {
        "userId", "fullName", "course", "mobile", "college"
    };

    for (const char* key : required) {
        if (!fields.count(key)) {
            respond(client, 400, "application/json",
                R"({"success":false,"message":"Please provide all profile details."})");
            return;
        }

    }

    std::string userId = fields.at("userId");
    std::string fullName = fields.at("fullName");
    std::string course = fields.at("course");
    std::string mobile = fields.at("mobile");
    std::string college = fields.at("college");
    std::string photo = fields.count("profilePhoto")
        ? fields.at("profilePhoto") : "";

    if (!isNumericId(userId) || fullName.empty() ||
        fullName.size() > 100 || course.size() > 100 ||
        mobile.size() > 10 || college.size() > 150) {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please check your profile details."})");
        return;
    }

    if (!photo.empty() &&
        (photo.size() > 700000 ||
         photo.rfind("data:image/", 0) != 0 ||
         photo.find(";base64,") == std::string::npos)) {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please select an image smaller than 500 KB."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db) {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    std::string sql =
        "UPDATE users SET "
        "full_name='" + escaped(db, fullName) + "', "
        "course='" + escaped(db, course) + "', "
        "mobile='" + escaped(db, mobile) + "', "
        "college='" + escaped(db, college) + "'";

    if (!photo.empty()) {
        sql += ", profile_photo='" + escaped(db, photo) + "'";
    }

    sql += " WHERE user_id=" + userId + " AND role='student'";

    if (mysql_query(db, sql.c_str()) != 0) {
        std::cerr << "Update profile SQL error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not update profile."})");
        return;
    }

    bool found = mysql_affected_rows(db) > 0;
    mysql_close(db);

    // A successful update can affect zero rows if nothing changed.
    if (!found) {
        MYSQL* checkDb = connectDB();
        if (!checkDb) {
            respond(client, 500, "application/json",
                R"({"success":false,"message":"Could not verify student account."})");
            return;
        }

        std::string checkSql =
            "SELECT user_id FROM users WHERE user_id=" + userId +
            " AND role='student' LIMIT 1";

        bool exists = mysql_query(checkDb, checkSql.c_str()) == 0;
        MYSQL_RES* checkResult = exists ? mysql_store_result(checkDb) : nullptr;
        MYSQL_ROW checkRow = checkResult ? mysql_fetch_row(checkResult) : nullptr;
        exists = checkRow != nullptr;

        if (checkResult) mysql_free_result(checkResult);
        mysql_close(checkDb);

        if (!exists) {
            respond(client, 404, "application/json",
                R"({"success":false,"message":"Student account not found."})");
            return;
        }
    }

    respond(client, 200, "application/json",
        R"({"success":true,"message":"Profile updated successfully!"})");
}


// ==================================================
// ADMIN STUDENTS API
// GET /api/admin/students?adminId=ID
// ==================================================

void handleAdminStudents(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("adminId") || !isNumericId(params.at("adminId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Admin login information is missing or invalid."})");
        return;
    }

    const std::string adminId = params.at("adminId");
    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    // Confirm that the requesting account is an administrator.
    const std::string verifySql =
        "SELECT admin_id FROM admins WHERE admin_id=" + adminId + " LIMIT 1";

    if (mysql_query(db, verifySql.c_str()) != 0)
    {
        std::cerr << "Admin students verification error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify admin account."})");
        return;
    }

    MYSQL_RES* verifyResult = mysql_store_result(db);
    if (!verifyResult)
    {
        std::cerr << "Admin students verification result error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read admin verification result."})");
        return;
    }

    MYSQL_ROW adminRow = mysql_fetch_row(verifyResult);
    mysql_free_result(verifyResult);

    if (!adminRow)
    {
        mysql_close(db);
        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid admin account. Please log in again."})");
        return;
    }

    const std::string sql =
        "SELECT user_id, full_name, username, email, "
        "COALESCE(course,''), COALESCE(mobile,''), COALESCE(college,''), "
        "DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s') "
        "FROM users WHERE role='student' ORDER BY created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Admin students SQL error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load student records. Check the users table columns."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);
    if (!result)
    {
        std::cerr << "Admin students result error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read student records."})");
        return;
    }

    std::ostringstream json;
    json << R"({"success":true,"students":[)";

    bool first = true;
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        auto value = [&](unsigned int index) -> std::string
        {
            return row[index] ? row[index] : "";
        };

        if (!first) json << ',';
        first = false;

        json << "{"
             << R"("userId":)" << value(0) << ','
             << R"("fullName":")" << jsonEscape(value(1)) << "\","
             << R"("username":")" << jsonEscape(value(2)) << "\","
             << R"("email":")" << jsonEscape(value(3)) << "\","
             << R"("course":")" << jsonEscape(value(4)) << "\","
             << R"("mobile":")" << jsonEscape(value(5)) << "\","
             << R"("college":")" << jsonEscape(value(6)) << "\","
             << R"("createdAt":")" << jsonEscape(value(7)) << "\"}";
    }

    json << "]}";

    mysql_free_result(result);
    mysql_close(db);

    respond(client, 200, "application/json", json.str());
}

// ==================================================
// ADMIN SKILLS API
// GET /api/admin/skills?adminId=ID
// ==================================================

void handleAdminSkills(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("adminId") || !isNumericId(params.at("adminId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Admin login information not found."})");
        return;
    }

    const std::string adminId = params.at("adminId");
    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string verifySql =
        "SELECT admin_id FROM admins WHERE admin_id=" + adminId + " LIMIT 1";

    if (mysql_query(db, verifySql.c_str()) != 0)
    {
        std::cerr << "Admin skills verification error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Admin verification failed."})");
        return;
    }

    MYSQL_RES* verifyResult = mysql_store_result(db);
    MYSQL_ROW adminRow = verifyResult ? mysql_fetch_row(verifyResult) : nullptr;

    if (!adminRow)
    {
        if (verifyResult) mysql_free_result(verifyResult);
        mysql_close(db);
        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid admin account."})");
        return;
    }
    mysql_free_result(verifyResult);

    const std::string sql =
        "SELECT s.skill_id, s.user_id, s.skill_name, s.skill_type, "
        "COALESCE(s.category,''), COALESCE(s.description,''), "
        "COALESCE(s.skill_level,''), COALESCE(s.experience,''), "
        "COALESCE(s.availability,''), COALESCE(u.full_name,''), "
        "COALESCE(u.username,''), "
        "DATE_FORMAT(s.created_at,'%Y-%m-%d %H:%i:%s') "
        "FROM skills s "
        "LEFT JOIN users u ON u.user_id=s.user_id "
        "ORDER BY s.created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Admin skills SQL error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load skills. Check the skills table columns."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);
    if (!result)
    {
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read skills."})");
        return;
    }

    std::ostringstream json;
    json << R"({"success":true,"skills":[)";
    bool first = true;
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        if (!first) json << ',';
        first = false;

        auto value = [&](unsigned int i) -> std::string {
            return row[i] ? row[i] : "";
        };

        json << "{"
             << R"("skillId":)" << value(0) << ','
             << R"("userId":)" << value(1) << ','
             << R"("skillName":")" << jsonEscape(value(2)) << "\","
             << R"("skillType":")" << jsonEscape(value(3)) << "\","
             << R"("category":")" << jsonEscape(value(4)) << "\","
             << R"("description":")" << jsonEscape(value(5)) << "\","
             << R"("skillLevel":")" << jsonEscape(value(6)) << "\","
             << R"("experience":")" << jsonEscape(value(7)) << "\","
             << R"("availability":")" << jsonEscape(value(8)) << "\","
             << R"("studentName":")" << jsonEscape(value(9)) << "\","
             << R"("username":")" << jsonEscape(value(10)) << "\","
             << R"("createdAt":")" << jsonEscape(value(11)) << "\"}";
    }

    json << "]}";
    mysql_free_result(result);
    mysql_close(db);
    respond(client, 200, "application/json", json.str());
}

// ==================================================
// ADMIN EXCHANGE REQUESTS API
// GET /api/admin/requests?adminId=ID
// ==================================================

void handleAdminRequests(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);
    if (!params.count("adminId") || !isNumericId(params.at("adminId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Admin login information is missing or invalid."})");
        return;
    }

    MYSQL* db = connectDB();
    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string verifySql =
        "SELECT admin_id FROM admins WHERE admin_id=" + params.at("adminId") + " LIMIT 1";
    if (mysql_query(db, verifySql.c_str()) != 0)
    {
        std::cerr << "Admin requests verification error: " << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify admin account."})");
        return;
    }

    MYSQL_RES* verifyResult = mysql_store_result(db);
    MYSQL_ROW adminRow = verifyResult ? mysql_fetch_row(verifyResult) : nullptr;
    if (!adminRow)
    {
        if (verifyResult) mysql_free_result(verifyResult);
        mysql_close(db);
        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid admin account. Please log in again."})");
        return;
    }
    mysql_free_result(verifyResult);

    const std::string sql =
        "SELECT r.request_id, r.skill_id, r.requester_id, r.receiver_id, "
        "COALESCE(s.skill_name,''), COALESCE(requester.full_name,''), "
        "COALESCE(receiver.full_name,''), COALESCE(r.message,''), "
        "COALESCE(r.response_message,''), COALESCE(r.status,'pending'), "
        "DATE_FORMAT(r.created_at,'%Y-%m-%d %H:%i:%s') "
        "FROM exchange_requests r "
        "LEFT JOIN skills s ON s.skill_id=r.skill_id "
        "LEFT JOIN users requester ON requester.user_id=r.requester_id "
        "LEFT JOIN users receiver ON receiver.user_id=r.receiver_id "
        "ORDER BY r.created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Admin requests SQL error: " << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load exchange requests. Check exchange_requests columns."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);
    if (!result)
    {
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read exchange requests."})");
        return;
    }

    std::ostringstream json;
    json << R"({"success":true,"requests":[)";
    bool first = true;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        auto value = [&](unsigned int i) -> std::string { return row[i] ? row[i] : ""; };
        if (!first) json << ',';
        first = false;
        json << "{"
             << R"("requestId":)" << value(0) << ','
             << R"("skillId":)" << value(1) << ','
             << R"("requesterId":)" << value(2) << ','
             << R"("receiverId":)" << value(3) << ','
             << R"("skillName":")" << jsonEscape(value(4)) << "\","
             << R"("requesterName":")" << jsonEscape(value(5)) << "\","
             << R"("receiverName":")" << jsonEscape(value(6)) << "\","
             << R"("message":")" << jsonEscape(value(7)) << "\","
             << R"("responseMessage":")" << jsonEscape(value(8)) << "\","
             << R"("status":")" << jsonEscape(value(9)) << "\","
             << R"("createdAt":")" << jsonEscape(value(10)) << "\"}";
    }
    json << "]}";
    mysql_free_result(result);
    mysql_close(db);
    respond(client, 200, "application/json", json.str());
}

// ==================================================
// STUDENT FEEDBACK APIs
// GET  /api/feedback/eligible?userId=ID
// POST /api/feedback
// ==================================================

void handleEligibleFeedback(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);
    if (!params.count("userId") || !isNumericId(params.at("userId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Student login information is missing or invalid."})");
        return;
    }

    const std::string userId = params.at("userId");
    MYSQL* db = connectDB();
    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string verifySql =
        "SELECT user_id FROM users WHERE user_id=" + userId +
        " AND role='student' LIMIT 1";

    if (mysql_query(db, verifySql.c_str()) != 0)
    {
        std::cerr << "Eligible feedback verification error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify student account."})");
        return;
    }

    MYSQL_RES* verifyResult = mysql_store_result(db);
    MYSQL_ROW studentRow = verifyResult ? mysql_fetch_row(verifyResult) : nullptr;
    if (!studentRow)
    {
        if (verifyResult) mysql_free_result(verifyResult);
        mysql_close(db);
        respond(client, 401, "application/json",
            R"({"success":false,"message":"Student account not found. Please log in again."})");
        return;
    }
    mysql_free_result(verifyResult);

    const std::string sql =
        "SELECT r.request_id, COALESCE(s.skill_name,''), "
        "CASE WHEN r.requester_id=" + userId +
        " THEN COALESCE(receiver.full_name,'') "
        "ELSE COALESCE(requester.full_name,'') END AS reviewee_name, "
        "CASE WHEN r.requester_id=" + userId +
        " THEN r.receiver_id ELSE r.requester_id END AS reviewee_id "
        "FROM exchange_requests r "
        "LEFT JOIN skills s ON s.skill_id=r.skill_id "
        "LEFT JOIN users requester ON requester.user_id=r.requester_id "
        "LEFT JOIN users receiver ON receiver.user_id=r.receiver_id "
        "WHERE r.status='completed' "
        "AND (r.requester_id=" + userId + " OR r.receiver_id=" + userId + ") "
        "AND NOT EXISTS (SELECT 1 FROM feedback f "
        "WHERE f.request_id=r.request_id AND f.reviewer_id=" + userId + ") "
        "ORDER BY r.created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Eligible feedback SQL error: " << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load completed exchanges. Check exchange_requests and feedback tables."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);
    if (!result)
    {
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read completed exchanges."})");
        return;
    }

    std::ostringstream json;
    json << R"({"success":true,"exchanges":[)";
    bool first = true;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        auto value = [&](unsigned int i) -> std::string {
            return row[i] ? row[i] : "";
        };

        if (!first) json << ',';
        first = false;

        json << "{"
             << R"("requestId":)" << value(0) << ','
             << R"("request_id":)" << value(0) << ','
             << R"("skillName":")" << jsonEscape(value(1)) << "\","
             << R"("revieweeName":")" << jsonEscape(value(2)) << "\","
             << R"("revieweeId":)" << value(3)
             << "}";
    }

    json << "]}";
    mysql_free_result(result);
    mysql_close(db);
    respond(client, 200, "application/json", json.str());
}

void handleSubmitFeedback(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    const std::string requestId =
        fields.count("requestId") ? fields.at("requestId") : "";
    const std::string reviewerId =
        fields.count("reviewerId") ? fields.at("reviewerId") :
        (fields.count("userId") ? fields.at("userId") : "");
    const std::string ratingText =
        fields.count("rating") ? fields.at("rating") : "";
    const std::string comment =
        fields.count("comment") ? fields.at("comment") : "";

    if (!isNumericId(requestId) || !isNumericId(reviewerId) ||
        !isNumericId(ratingText) || comment.size() > 5000)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid feedback details. Please select an exchange and rating."})");
        return;
    }

    const int rating = std::atoi(ratingText.c_str());
    if (rating < 1 || rating > 5)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please select a rating from 1 to 5 stars."})");
        return;
    }

    MYSQL* db = connectDB();
    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    // Confirm the reviewer is a student and a participant in this completed exchange.
    const std::string checkSql =
        "SELECT requester_id, receiver_id "
        "FROM exchange_requests "
        "WHERE request_id=" + requestId +
        " AND status='completed' "
        "AND (requester_id=" + reviewerId +
        " OR receiver_id=" + reviewerId + ") LIMIT 1";

    if (mysql_query(db, checkSql.c_str()) != 0)
    {
        std::cerr << "Submit feedback verification error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify the completed exchange."})");
        return;
    }

    MYSQL_RES* checkResult = mysql_store_result(db);
    MYSQL_ROW exchangeRow = checkResult ? mysql_fetch_row(checkResult) : nullptr;
    if (!exchangeRow || !exchangeRow[0] || !exchangeRow[1])
    {
        if (checkResult) mysql_free_result(checkResult);
        mysql_close(db);
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Feedback can be submitted only by a participant in a completed exchange."})");
        return;
    }

    const std::string requesterId = exchangeRow[0];
    const std::string receiverId = exchangeRow[1];
    const std::string revieweeId =
        (reviewerId == requesterId) ? receiverId : requesterId;
    mysql_free_result(checkResult);

    const std::string reviewerCheckSql =
        "SELECT user_id FROM users WHERE user_id=" + reviewerId +
        " AND role='student' LIMIT 1";
    if (mysql_query(db, reviewerCheckSql.c_str()) != 0)
    {
        std::cerr << "Feedback reviewer SQL error: " << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify reviewer account."})");
        return;
    }

    MYSQL_RES* reviewerResult = mysql_store_result(db);
    MYSQL_ROW reviewerRow = reviewerResult ? mysql_fetch_row(reviewerResult) : nullptr;
    if (!reviewerRow)
    {
        if (reviewerResult) mysql_free_result(reviewerResult);
        mysql_close(db);
        respond(client, 401, "application/json",
            R"({"success":false,"message":"Student account not found. Please log in again."})");
        return;
    }
    mysql_free_result(reviewerResult);

    const std::string duplicateSql =
        "SELECT feedback_id FROM feedback WHERE request_id=" + requestId +
        " AND reviewer_id=" + reviewerId + " LIMIT 1";

    if (mysql_query(db, duplicateSql.c_str()) != 0)
    {
        std::cerr << "Feedback duplicate check error: " << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not check existing feedback."})");
        return;
    }

    MYSQL_RES* duplicateResult = mysql_store_result(db);
    MYSQL_ROW duplicateRow = duplicateResult ? mysql_fetch_row(duplicateResult) : nullptr;
    if (duplicateRow)
    {
        mysql_free_result(duplicateResult);
        mysql_close(db);
        respond(client, 409, "application/json",
            R"({"success":false,"message":"You have already submitted feedback for this exchange."})");
        return;
    }
    if (duplicateResult) mysql_free_result(duplicateResult);

    const std::string safeComment = escaped(db, comment);
    const std::string insertSql =
        "INSERT INTO feedback "
        "(request_id, reviewer_id, reviewee_id, rating, comment) VALUES (" +
        requestId + ", " + reviewerId + ", " + revieweeId + ", " +
        std::to_string(rating) + ", '" + safeComment + "')";

    if (mysql_query(db, insertSql.c_str()) != 0)
    {
        std::cerr << "Insert feedback SQL error: " << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not save feedback. Check the feedback table structure."})");
        return;
    }

    mysql_close(db);
    respond(client, 200, "application/json",
        R"({"success":true,"message":"Thank you! Your feedback has been submitted successfully."})");
}

// ==================================================
// ADMIN FEEDBACK API
// GET /api/admin/feedback?adminId=ID
// ==================================================

void handleSystemFeedback(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    if (!fields.count("userId") ||
        !fields.count("rating") ||
        !isNumericId(fields.at("userId")) ||
        !isNumericId(fields.at("rating")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid student ID or rating."})");
        return;
    }

    const std::string userId = fields.at("userId");
    const int rating = std::atoi(fields.at("rating").c_str());
    const std::string comment =
        fields.count("comment") ? fields.at("comment") : "";

    if (rating < 1 || rating > 5 || comment.size() > 2000)
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please select 1 to 5 stars and keep feedback under 2000 characters."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string verifySql =
        "SELECT user_id FROM users WHERE user_id=" + userId +
        " AND role='student' LIMIT 1";

    if (mysql_query(db, verifySql.c_str()) != 0)
    {
        std::cerr << "System feedback student check error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify student account."})");
        return;
    }

    MYSQL_RES* verifyResult = mysql_store_result(db);
    MYSQL_ROW studentRow = verifyResult ? mysql_fetch_row(verifyResult) : nullptr;

    if (!studentRow)
    {
        if (verifyResult) mysql_free_result(verifyResult);
        mysql_close(db);
        respond(client, 401, "application/json",
            R"({"success":false,"message":"Student account not found. Please log in again."})");
        return;
    }

    mysql_free_result(verifyResult);

    const std::string safeComment = escaped(db, comment);
    const std::string insertSql =
        "INSERT INTO feedback "
        "(request_id, reviewer_id, reviewee_id, rating, comment) "
        "VALUES (NULL, " + userId + ", NULL, " +
        std::to_string(rating) + ", '" + safeComment + "')";

    if (mysql_query(db, insertSql.c_str()) != 0)
    {
        std::cerr << "System feedback insert error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not save feedback. Check the feedback table and its foreign keys."})");
        return;
    }

    mysql_close(db);

    respond(client, 200, "application/json",
        R"({"success":true,"message":"Thank you! Your feedback was submitted successfully."})");
}

void handleAdminFeedback(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("adminId") ||
        !isNumericId(params.at("adminId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Admin login information is missing or invalid."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    // Verify admin account
    const std::string verifySql =
        "SELECT admin_id FROM admins WHERE admin_id=" +
        params.at("adminId") + " LIMIT 1";

    if (mysql_query(db, verifySql.c_str()) != 0)
    {
        std::cerr << "Admin verification error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify admin account."})");
        return;
    }

    MYSQL_RES* verifyResult = mysql_store_result(db);

    if (!verifyResult)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read admin account."})");
        return;
    }

    MYSQL_ROW adminRow = mysql_fetch_row(verifyResult);

    if (!adminRow)
    {
        mysql_free_result(verifyResult);
        mysql_close(db);

        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid admin account. Please log in again."})");
        return;
    }

    mysql_free_result(verifyResult);

    // Load general system feedback.
    // No request_id or reviewee_id is required.
    const std::string sql =
        "SELECT "
        "f.feedback_id, "
        "f.reviewer_id, "
        "COALESCE(u.full_name,''), "
        "COALESCE(f.rating,0), "
        "COALESCE(f.comment,''), "
        "DATE_FORMAT(f.created_at,'%Y-%m-%d %H:%i:%s') "
        "FROM feedback f "
        "LEFT JOIN users u ON u.user_id = f.reviewer_id "
        "ORDER BY f.created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Admin feedback SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load feedback. Check feedback table columns."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read feedback records."})");
        return;
    }

    std::ostringstream json;

    json << R"({"success":true,"feedback":[)";

    bool first = true;
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        auto value = [&](unsigned int i) -> std::string
        {
            return row[i] ? row[i] : "";
        };

        if (!first)
            json << ',';

        first = false;

        json << "{"
             << R"("feedbackId":)" << value(0) << ','
             << R"("reviewerId":)" << value(1) << ','
             << R"("reviewerName":")" << jsonEscape(value(2)) << "\","
             << R"("rating":)" << value(3) << ','
             << R"("comment":")" << jsonEscape(value(4)) << "\","
             << R"("createdAt":")" << jsonEscape(value(5)) << "\""
             << "}";
    }

    json << "]}";

    mysql_free_result(result);
    mysql_close(db);

    respond(client, 200, "application/json", json.str());
}

// ==================================================
// REMOVE STUDENT API
// POST /api/admin/students/remove
// Permanently removes the student's feedback, requests, skills and account.
// ==================================================

void handleAdminRemoveStudent(SOCKET client, const std::string& body)
{
    const auto fields = parseForm(body);

    if (!fields.count("adminId") || !isNumericId(fields.at("adminId")) ||
        !fields.count("userId") || !isNumericId(fields.at("userId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid admin or student ID."})");
        return;
    }

    const std::string adminId = fields.at("adminId");
    const std::string userId = fields.at("userId");

    MYSQL* db = connectDB();
    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string verifyAdminSql =
        "SELECT admin_id FROM admins WHERE admin_id=" + adminId + " LIMIT 1";

    if (mysql_query(db, verifyAdminSql.c_str()) != 0)
    {
        std::cerr << "Remove student admin verification error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify admin account."})");
        return;
    }

    MYSQL_RES* adminResult = mysql_store_result(db);
    MYSQL_ROW adminRow = adminResult ? mysql_fetch_row(adminResult) : nullptr;
    if (!adminRow)
    {
        if (adminResult) mysql_free_result(adminResult);
        mysql_close(db);
        respond(client, 401, "application/json",
            R"({"success":false,"message":"Invalid admin account."})");
        return;
    }
    mysql_free_result(adminResult);

    const std::string verifyStudentSql =
        "SELECT user_id FROM users WHERE user_id=" + userId +
        " AND role='student' LIMIT 1";

    if (mysql_query(db, verifyStudentSql.c_str()) != 0)
    {
        std::cerr << "Remove student verification error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify student account."})");
        return;
    }

    MYSQL_RES* studentResult = mysql_store_result(db);
    MYSQL_ROW studentRow = studentResult ? mysql_fetch_row(studentResult) : nullptr;
    if (!studentRow)
    {
        if (studentResult) mysql_free_result(studentResult);
        mysql_close(db);
        respond(client, 404, "application/json",
            R"({"success":false,"message":"Student account was not found."})");
        return;
    }
    mysql_free_result(studentResult);

    if (mysql_query(db, "START TRANSACTION") != 0)
    {
        std::cerr << "Remove student transaction error: "
                  << mysql_error(db) << '\n';
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not start database transaction."})");
        return;
    }

    // Remove dependent records first to avoid foreign-key conflicts.
    const std::string deleteFeedbackSql =
        "DELETE FROM feedback WHERE reviewer_id=" + userId +
        " OR reviewee_id=" + userId +
        " OR request_id IN (SELECT request_id FROM exchange_requests "
        "WHERE requester_id=" + userId + " OR receiver_id=" + userId + ")";

    const std::string deleteRequestsSql =
        "DELETE FROM exchange_requests WHERE requester_id=" + userId +
        " OR receiver_id=" + userId;

    const std::string deleteSkillsSql =
        "DELETE FROM skills WHERE user_id=" + userId;

    const std::string deleteUserSql =
        "DELETE FROM users WHERE user_id=" + userId + " AND role='student'";

    const std::string* statements[] = {
        &deleteFeedbackSql, &deleteRequestsSql, &deleteSkillsSql, &deleteUserSql
    };

    for (const std::string* statement : statements)
    {
        if (mysql_query(db, statement->c_str()) != 0)
        {
            std::cerr << "Remove student SQL error: "
                      << mysql_error(db) << '\n';
            mysql_query(db, "ROLLBACK");
            mysql_close(db);
            respond(client, 500, "application/json",
                R"({"success":false,"message":"Student could not be removed. Database rejected the operation; no changes were committed."})");
            return;
        }
    }

    if (mysql_affected_rows(db) == 0)
    {
        mysql_query(db, "ROLLBACK");
        mysql_close(db);
        respond(client, 404, "application/json",
            R"({"success":false,"message":"Student account was not removed."})");
        return;
    }

    if (mysql_query(db, "COMMIT") != 0)
    {
        std::cerr << "Remove student commit error: "
                  << mysql_error(db) << '\n';
        mysql_query(db, "ROLLBACK");
        mysql_close(db);
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not finish removing student."})");
        return;
    }

    mysql_close(db);
    respond(client, 200, "application/json",
        R"({"success":true,"message":"Student and related records were removed successfully."})");
}

void handleMySkills(SOCKET client, const std::string& queryString)
{
    const auto params = parseForm(queryString);

    if (!params.count("userId") || !isNumericId(params.at("userId")))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid student ID."})");
        return;
    }

    const std::string userId = params.at("userId");

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    const std::string sql =
        "SELECT skill_id, skill_name, skill_type, category, "
        "description, skill_level, experience, availability, "
        "DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s') "
        "FROM skills WHERE user_id=" + userId +
        " ORDER BY created_at DESC";

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "My Skills SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not load student skills."})");
        return;
    }

    MYSQL_RES* result = mysql_store_result(db);

    if (!result)
    {
        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not read student skills."})");
        return;
    }

    std::ostringstream json;
    json << R"({"success":true,"skills":[)";

    bool first = true;
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result)) != nullptr)
    {
        auto value = [&](unsigned int i) -> std::string
        {
            return row[i] ? row[i] : "";
        };

        if (!first) json << ',';
        first = false;

        json << "{"
             << R"("skillId":)" << value(0) << ','
             << R"("skillName":")" << jsonEscape(value(1)) << "\","
             << R"("skillType":")" << jsonEscape(value(2)) << "\","
             << R"("category":")" << jsonEscape(value(3)) << "\","
             << R"("description":")" << jsonEscape(value(4)) << "\","
             << R"("skillLevel":")" << jsonEscape(value(5)) << "\","
             << R"("experience":")" << jsonEscape(value(6)) << "\","
             << R"("availability":")" << jsonEscape(value(7)) << "\","
             << R"("createdAt":")" << jsonEscape(value(8)) << "\""
             << "}";
    }

    json << "]}";

    mysql_free_result(result);
    mysql_close(db);

    respond(client, 200, "application/json", json.str());
}

bool getJsonString(const std::string& json,
                   const std::string& key,
                   std::string& value)
{
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);

    if (pos == std::string::npos) return false;

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return false;

    pos++;

    while (pos < json.size() &&
           std::isspace(static_cast<unsigned char>(json[pos])))
        pos++;

    if (pos >= json.size() || json[pos] != '"')
        return false;

    pos++;
    value.clear();

    while (pos < json.size())
    {
        char c = json[pos++];

        if (c == '"') return true;

        if (c == '\\')
        {
            if (pos >= json.size()) return false;

            char escapedChar = json[pos++];

            switch (escapedChar)
            {
                case '"': value += '"'; break;
                case '\\': value += '\\'; break;
                case '/': value += '/'; break;
                case 'n': value += '\n'; break;
                case 'r': value += '\r'; break;
                case 't': value += '\t'; break;
                case 'b': value += '\b'; break;
                case 'f': value += '\f'; break;
                default: return false;
            }
        }
        else
        {
            value += c;
        }
    }

    return false;
}

bool getJsonNumber(const std::string& json,
                   const std::string& key,
                   std::string& value)
{
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);

    if (pos == std::string::npos) return false;

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return false;

    pos++;

    while (pos < json.size() &&
           std::isspace(static_cast<unsigned char>(json[pos])))
        pos++;

    size_t start = pos;

    while (pos < json.size() &&
           std::isdigit(static_cast<unsigned char>(json[pos])))
        pos++;

    if (start == pos) return false;

    value = json.substr(start, pos - start);
    return true;
}



void handleUpdateSkill(SOCKET client, const std::string& body)
{
    std::string skillId, userId;
    std::string skillName, skillType, category;
    std::string skillLevel, experience;
    std::string availability, description;

    // Read numeric fields
    if (!getJsonNumber(body, "skill_id", skillId) ||
        !getJsonNumber(body, "user_id", userId) ||
        !isNumericId(skillId) ||
        !isNumericId(userId))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid skill or student ID."})");
        return;
    }

    // Read text fields
    if (!getJsonString(body, "skill_name", skillName) ||
        !getJsonString(body, "skill_type", skillType) ||
        !getJsonString(body, "category", category) ||
        !getJsonString(body, "skill_level", skillLevel) ||
        !getJsonString(body, "experience", experience) ||
        !getJsonString(body, "availability", availability) ||
        !getJsonString(body, "description", description))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Invalid skill information."})");
        return;
    }

    // Validate fields
    if (skillName.empty() ||
        skillName.size() > 100 ||
        category.size() > 100 ||
        skillLevel.size() > 30 ||
        experience.size() > 50 ||
        availability.size() > 30 ||
        (skillType != "teach" && skillType != "learn"))
    {
        respond(client, 400, "application/json",
            R"({"success":false,"message":"Please check the skill details."})");
        return;
    }

    MYSQL* db = connectDB();

    if (!db)
    {
        respond(client, 500, "application/json",
            R"({"success":false,"message":"Database connection failed."})");
        return;
    }

    // Verify that this skill belongs to the logged-in student.
    const std::string checkSql =
        "SELECT skill_id FROM skills WHERE skill_id=" +
        skillId + " AND user_id=" + userId + " LIMIT 1";

    if (mysql_query(db, checkSql.c_str()) != 0)
    {
        std::cerr << "Update Skill verification error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not verify skill."})");
        return;
    }

    MYSQL_RES* checkResult = mysql_store_result(db);
    MYSQL_ROW row = checkResult ? mysql_fetch_row(checkResult) : nullptr;

    if (!row)
    {
        if (checkResult) mysql_free_result(checkResult);
        mysql_close(db);

        respond(client, 404, "application/json",
            R"({"success":false,"message":"Skill not found or you do not have permission to edit it."})");
        return;
    }

    mysql_free_result(checkResult);

    // Escape text before using it in SQL.
    std::string safeName = escaped(db, skillName);
    std::string safeType = escaped(db, skillType);
    std::string safeCategory = escaped(db, category);
    std::string safeLevel = escaped(db, skillLevel);
    std::string safeExperience = escaped(db, experience);
    std::string safeAvailability = escaped(db, availability);
    std::string safeDescription = escaped(db, description);

    const std::string sql =
        "UPDATE skills SET "
        "skill_name='" + safeName + "', "
        "skill_type='" + safeType + "', "
        "category='" + safeCategory + "', "
        "skill_level='" + safeLevel + "', "
        "experience='" + safeExperience + "', "
        "availability='" + safeAvailability + "', "
        "description='" + safeDescription + "' "
        "WHERE skill_id=" + skillId +
        " AND user_id=" + userId;

    if (mysql_query(db, sql.c_str()) != 0)
    {
        std::cerr << "Update Skill SQL error: "
                  << mysql_error(db) << '\n';

        mysql_close(db);

        respond(client, 500, "application/json",
            R"({"success":false,"message":"Could not update skill."})");
        return;
    }

    mysql_close(db);

    respond(client, 200, "application/json",
        R"({"success":true,"message":"Skill updated successfully!"})");
}

// ==================================================
// MAIN WEB SERVER
// ==================================================

int main()
{
    WSADATA wsa{};

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "Winsock initialization failed.\n";
        return 1;
    }

    SOCKET server = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (server == INVALID_SOCKET)
    {
        std::cerr << "Socket creation failed: "
                  << WSAGetLastError() << '\n';

        WSACleanup();
        return 1;
    }

    BOOL reuseAddress = TRUE;

    setsockopt(
        server,
        SOL_SOCKET,
        SO_REUSEADDR,
        reinterpret_cast<const char*>(&reuseAddress),
        sizeof(reuseAddress)
    );

    sockaddr_in address{};

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(8080);

    if (bind(
        server,
        reinterpret_cast<sockaddr*>(&address),
        sizeof(address)) == SOCKET_ERROR)
    {
        std::cerr << "Bind failed: "
                  << WSAGetLastError()
                  << ". Is port 8080 already in use?\n";

        closesocket(server);
        WSACleanup();
        return 1;
    }

    if (listen(server, SOMAXCONN) == SOCKET_ERROR)
    {
        std::cerr << "Listen failed: "
                  << WSAGetLastError() << '\n';

        closesocket(server);
        WSACleanup();
        return 1;
    }

    // HTML PAGE ROUTES

    
const std::map<std::string, std::string> pages = {
    { "/", "main.html" },
    { "/main.html", "main.html" },
    { "/register.html", "register.html" },
    { "/login.html", "login.html" },
    { "/student_dash.html", "student_dash.html" },
    { "/my_skills.html", "my_skills.html" },
    { "/add-skill.html", "add-skill.html" },
    { "/explore.html", "explore.html" },
    { "/requests.html", "requests.html" },
    { "/students.html", "students.html" },
    { "/profile.html", "profile.html" },
    { "/admin-login.html", "admin-login.html" },
    { "/admin_dash.html", "admin_dash.html" },
    { "/feedback.html", "feedback.html" },
};


    std::cout << "\n====================================\n";
    std::cout << " CAMPUS SKILL EXCHANGE SYSTEM\n";
    std::cout << "====================================\n";
    std::cout << "Server running successfully!\n";
    std::cout << "http://127.0.0.1:8080/\n";
    std::cout << "Press Ctrl+C to stop.\n\n";

    while (true)
    {
        SOCKET client = accept(server, nullptr, nullptr);

        if (client == INVALID_SOCKET)
        {
            std::cerr << "Accept failed: "
                      << WSAGetLastError() << '\n';
            continue;
        }

        std::string request;

        if (!readRequest(client, request))
        {
            respond(client, 400, "text/plain",
                "Invalid or incomplete HTTP request.");

            shutdown(client, SD_BOTH);
            closesocket(client);
            continue;
        }

        size_t headerEnd = request.find("\r\n\r\n");
        size_t bodyStart = headerEnd + 4;

        std::istringstream firstLine(
            request.substr(0, request.find("\r\n"))
        );

        std::string method;
        std::string path;
        std::string version;

        firstLine >> method >> path >> version;

        std::string body = request.substr(bodyStart);

        // Extract query string.

        std::string queryString;
        size_t queryPosition = path.find('?');

        if (queryPosition != std::string::npos)
        {
            queryString = path.substr(queryPosition + 1);
            path.resize(queryPosition);
        }

        // REGISTRATION

        if (method == "POST" && path == "/api/register")
        {
            handleRegister(client, body);
        }

        // LOGIN

        else if (method == "POST" && path == "/api/login")
        {
            handleLogin(client, body);
        }
        else if (method == "POST" && path == "/api/admin/login")
        {
            handleAdminLogin(client, body);
        }

        // ADD SKILL

        else if (method == "POST" && path == "/api/skills")
        {
            handleAddSkill(client, body);
        }

        // EXPLORE SKILLS

        else if (method == "GET" && path == "/api/skills")
        {
            handleExploreSkills(client, queryString);
        }

        // SEND SKILL REQUEST

        else if (method == "POST" && path == "/api/requests")
        {
            handleCreateRequest(client, body);
        }

        // VIEW REQUESTS

        else if (method == "GET" && path == "/api/requests")
        {
            handleGetRequests(client, queryString);
        }

        // REPLY TO REQUEST

        else if (method == "POST" && path == "/api/reply")
        {
            handleReply(client, body);
        }
        // STUDENT DASHBOARD

else if (method == "GET" && path == "/api/dashboard")
{
    handleDashboard(client, queryString);
}
// GET STUDENT PROFILE
else if (method == "GET" && path == "/api/profile")
{
    handleGetProfile(client, queryString);
}
else if (method == "GET" && path == "/api/admin/dashboard")
{
    handleAdminDashboard(client, queryString);
}

else if (method == "GET" && path == "/api/admin/students")
{
    handleAdminStudents(client, queryString);
}

else if (method == "POST" && path == "/api/admin/students/remove")
{
    handleAdminRemoveStudent(client, body);
}

else if (method == "GET" && path == "/api/admin/skills")
{
    handleAdminSkills(client, queryString);
}

else if (method == "GET" && path == "/api/admin/requests")
{
    handleAdminRequests(client, queryString);
}

else if (method == "GET" && path == "/api/feedback/eligible")
{
    handleEligibleFeedback(client, queryString);
}
else if (method == "POST" && path == "/api/feedback")
{
    handleSubmitFeedback(client, body);
}
else if (method == "POST" && path == "/api/system-feedback")
{
    handleSystemFeedback(client, body);
}
else if (method == "GET" && path == "/api/admin/feedback")
{
    handleAdminFeedback(client, queryString);
}

// UPDATE STUDENT PROFILE
else if (method == "POST" && path == "/api/profile/update")
{
    handleUpdateProfile(client, body);
}

else if (method == "GET" && path == "/api/my-skills")
{
    handleMySkills(client, queryString);
}
else if (method == "PUT" && path == "/api/update-skill")
{
    handleUpdateSkill(client, body);
}
        // UNSUPPORTED METHOD

        else if (method != "GET")
        {
            respond(client, 405, "text/plain",
                "Method not allowed.");
        }

        // SERVE HTML PAGES

        else
        {
            auto page = pages.find(path);

            if (page == pages.end())
            {
                respond(client, 404, "text/plain",
                    "404 - Page not found.");
            }
            else
            {
                const std::string html = readFile(page->second);

                if (html.empty())
                {
                    std::cerr << "Could not read file: "
                              << page->second << '\n';

                    respond(client, 404, "text/plain",
                        "Could not find file: " + page->second);
                }
                else
                {
                    respond(client, 200, "text/html", html);

                    std::cout << "Page served: "
                              << page->second << '\n';
                }
            }
        }

        shutdown(client, SD_BOTH);
        closesocket(client);
    }

    closesocket(server);
    WSACleanup();

    return 0;
}
