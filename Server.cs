//using System;
//using MySql.Data.MySqlClient;

//namespace Unturend_Injector
//{
//    class Database
//    {
//        private readonly string _connectionString;

//        public Database(string server, string database, string user, string password, int port = 3307)
//        {
//            _connectionString = $"Server={server};Database={database};User ID={user};Password={password};Port={port};";
//            CreateTableIfNotExists(); // Создаем таблицу, если она не существует
//        }

//        // Метод для создания таблицы, если она не существует
//        public void CreateTableIfNotExists()
//        {
//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = @"
//                        CREATE TABLE IF NOT EXISTS users (
//                            id INT AUTO_INCREMENT PRIMARY KEY,
//                            username VARCHAR(255) NOT NULL,
//                            ip VARCHAR(45) NOT NULL,
//                            hwid VARCHAR(255) NOT NULL,
//                            banned BOOLEAN DEFAULT FALSE,
//                            role ENUM('user', 'premium', 'admin') DEFAULT 'user', -- Новое поле для ролей
//                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//                        );";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.ExecuteNonQuery();
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при создании таблицы: {ex.Message}");
//                Console.ResetColor();
//            }
//        }

//        // Метод для проверки существования пользователя
//        public bool UserExists(string hwid, string username)
//        {
//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "SELECT COUNT(*) FROM users WHERE hwid = @hwid OR username = @username";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        command.Parameters.AddWithValue("@username", username);
//                        var result = (long)command.ExecuteScalar();
//                        return result > 0;
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при проверке пользователя: {ex.Message}");
//                Console.ResetColor();
//                return false;
//            }
//        }

//        // Метод для добавления пользователя
//        public void AddUser(string username, string ip, string hwid, string role = "user")
//        {
//            if (UserExists(hwid, username))
//            {
//                Console.ForegroundColor = ConsoleColor.Yellow;
//                Console.WriteLine("Пользователь уже существует в базе данных.");
//                Console.ResetColor();
//                return;
//            }

//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "INSERT INTO users (username, ip, hwid, role) VALUES (@username, @ip, @hwid, @role)";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@username", username);
//                        command.Parameters.AddWithValue("@ip", ip);
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        command.Parameters.AddWithValue("@role", role);
//                        command.ExecuteNonQuery();
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при добавлении пользователя: {ex.Message}");
//                Console.ResetColor();
//            }
//        }

//        // Метод для проверки, забанен ли пользователь
//        public bool IsUserBanned(string hwid)
//        {
//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "SELECT banned FROM users WHERE hwid = @hwid";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        var result = command.ExecuteScalar();
//                        return result != null && (bool)result;
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при проверке бана: {ex.Message}");
//                Console.ResetColor();
//                return false;
//            }
//        }

//        // Метод для бана пользователя
//        public void BanUser(string hwid)
//        {
//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "UPDATE users SET banned = TRUE WHERE hwid = @hwid";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        command.ExecuteNonQuery();
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при бане пользователя: {ex.Message}");
//                Console.ResetColor();
//            }
//        }

//        // Метод для разбана пользователя
//        public void UnbanUser(string hwid)
//        {
//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "UPDATE users SET banned = FALSE WHERE hwid = @hwid";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        command.ExecuteNonQuery();
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при разбане пользователя: {ex.Message}");
//                Console.ResetColor();
//            }
//        }

//        // Метод для получения роли пользователя
//        public string GetUserRole(string hwid)
//        {
//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "SELECT role FROM users WHERE hwid = @hwid";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        var result = command.ExecuteScalar() as string;
//                        return result ?? "user"; // По умолчанию роль "user"
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при получении роли пользователя: {ex.Message}");
//                Console.ResetColor();
//                return "user";
//            }
//        }

//        // Метод для обновления роли пользователя
//        public void UpdateUserRole(string hwid, string role)
//        {
//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "UPDATE users SET role = @role WHERE hwid = @hwid";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@role", role);
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        command.ExecuteNonQuery();
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при обновлении роли пользователя: {ex.Message}");
//                Console.ResetColor();
//            }
//        }

//        // Метод для создания аккаунта с ролью
//        public void CreateAccount(string username, string ip, string hwid, string role = "user")
//        {
//            if (UserExists(hwid, username))
//            {
//                Console.ForegroundColor = ConsoleColor.Yellow;
//                Console.WriteLine("Пользователь уже существует в базе данных.");
//                Console.ResetColor();
//                return;
//            }

//            try
//            {
//                using (var connection = new MySqlConnection(_connectionString))
//                {
//                    connection.Open();
//                    var query = "INSERT INTO users (username, ip, hwid, role) VALUES (@username, @ip, @hwid, @role)";
//                    using (var command = new MySqlCommand(query, connection))
//                    {
//                        command.Parameters.AddWithValue("@username", username);
//                        command.Parameters.AddWithValue("@ip", ip);
//                        command.Parameters.AddWithValue("@hwid", hwid);
//                        command.Parameters.AddWithValue("@role", role);
//                        command.ExecuteNonQuery();
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"Ошибка при создании аккаунта: {ex.Message}");
//                Console.ResetColor();
//            }
//        }
//    }
//}