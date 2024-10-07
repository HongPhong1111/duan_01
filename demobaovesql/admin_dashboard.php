<?php
session_start();
include 'db_connection.php';

// Kiểm tra nếu admin đã đăng nhập và có quyền admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: login_handler.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Hệ thống ngân hàng</title>
    <link rel="stylesheet" href="style.css"> <!-- Đường dẫn tới file CSS -->
</head>
<body class="admmin-page">
    <div class="container">
        <h1>Admin Dashboard</h1>
        <h2>Danh sách tất cả các tài khoản:</h2>

        <table>
            <thead>
                <tr>
                    <th>Tên tài khoản</th>
                    <th>Truy cập tài khoản</th>
                    <th>Lịch sử giao dịch</th>
                    <th>Thao tác</th>
                </tr>
            </thead>
            <tbody>
                <?php
                // Truy vấn danh sách người dùng
                $query = "SELECT * FROM users";
                $result = $conn->query($query);

                while ($row = $result->fetch_assoc()) {
                    echo "<tr>";
                    echo "<td>" . htmlspecialchars($row['username']) . "</td>";
                    echo "<td><a href='account.php?user_id=" . $row['id'] . "'>Truy cập tài khoản</a></td>";
                    echo "<td><a href='transaction_history.php?user_id=" . $row['id'] . "'>Xem lịch sử giao dịch</a></td>";
                    echo "<td><a href='admin_withdraw.php?user_id=" . $row['id'] . "'>Thao tác rút tiền</a></td>";
                    echo "</tr>";
                }
                ?>
            </tbody>
        </table>
    </div>
</body>
</html>
