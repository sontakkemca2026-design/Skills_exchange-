
#include <iostream>
#include <mariadb/mysql.h>
#include "db_config.h"

int main()
{
    MYSQL* conn = mysql_init(nullptr);

    if (conn == nullptr)
    {
        std::cerr << "MySQL initialization failed.\n";
        return 1;
    }

    // Disable SSL requirement for local XAMPP development.
    my_bool ssl_enforce = 0;
    my_bool ssl_verify = 0;

    if (mysql_options(conn, MYSQL_OPT_SSL_ENFORCE,
                      &ssl_enforce) != 0)
    {
        std::cerr << "SSL configuration error: "
                  << mysql_error(conn) << '\n';
        mysql_close(conn);
        return 1;
    }

    if (mysql_options(conn, MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
                      &ssl_verify) != 0)
    {
        std::cerr << "SSL verification configuration error: "
                  << mysql_error(conn) << '\n';
        mysql_close(conn);
        return 1;
    }

    std::cout << "Connecting to XAMPP MariaDB...\n";

    if (mysql_real_connect(
            conn,
            DB_HOST,
            DB_USER,
            DB_PASSWORD,
            DB_NAME,
            DB_PORT,
            nullptr,
            0) == nullptr)
    {
        std::cerr << "Database connection failed!\n";
        std::cerr << "Error: " << mysql_error(conn) << '\n';
        std::cerr << "Error code: " << mysql_errno(conn) << '\n';

        mysql_close(conn);
        return 1;
    }

    std::cout << "Database connected successfully!\n";

    std::cout << "Database: " << mysql_get_server_info(conn) << '\n';

    mysql_close(conn);

    return 0;
}
