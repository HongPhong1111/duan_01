<?php
session_start();
include 'db_connection.php';

// Lấy user_id từ URL
$target_user_id = $_GET['user_id'];

// Lấy user_id và vai trò của người dùng hiện tại từ session
$current_user_id = $_SESSION['user_id'];
$role = $_SESSION['role'];

// Hàm kiểm tra quyền truy cập lịch sử giao dịch
function canViewTransactionHistory($current_user_id, $target_user_id, $role) {
    // Nếu là admin, có thể xem tất cả các tài khoản
    if ($role === 'admin') {
        return true;
    }

    // Nếu là người dùng thông thường, chỉ có thể xem tài khoản của chính mình
    if ($role === 'user' && $current_user_id === $target_user_id) {
        return true;
    }

    // Trường hợp còn lại, không có quyền truy cập
    return false;
}

// Kiểm tra quyền truy cập
if (canViewTransactionHistory($current_user_id, $target_user_id, $role)) {
    // Truy vấn thông tin tài khoản và thông tin cá nhân của người dùng
    $query = "SELECT u.username, u.created_at, a.balance FROM users u 
              JOIN accounts a ON u.id = a.user_id WHERE u.id = ?";
    
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $target_user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user_info = $result->fetch_assoc();

    if ($user_info) {
        $username = htmlspecialchars($user_info['username']);
        $created_at = htmlspecialchars($user_info['created_at']);
        $balance = number_format($user_info['balance'], 2) . " VND";
    } else {
        echo "Không tìm thấy thông tin người dùng.";
        exit;
    }

    // Truy vấn lịch sử giao dịch của người dùng
    $transaction_query = "SELECT * FROM transactions WHERE user_id = ?";
    $stmt = $conn->prepare($transaction_query);
    $stmt->bind_param("i", $target_user_id);
    $stmt->execute();
    $transaction_result = $stmt->get_result();

} else {
    echo "Bạn không có quyền truy cập vào lịch sử giao dịch này.";
    exit;
}
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chi tiết tài khoản - Hệ thống ngân hàng</title>
    <link rel="stylesheet" href="style.css"> 
</head>
<body class="account-page">
    <div class="container">
        <h1>Thông tin tài khoản của <?php echo $username; ?></h1>

        <h2>Thông tin cá nhân</h2>
        <p><strong>Tên tài khoản:</strong> <?php echo $username; ?></p>
        <p><strong>Ngày tạo tài khoản:</strong> <?php echo $created_at; ?></p>

        <h2>Thông tin tài khoản</h2>
        <p><strong>Số dư hiện tại:</strong> <?php echo $balance; ?></p>

        <h2>Lịch sử giao dịch</h2>
        <?php if ($transaction_result->num_rows > 0): ?>
            <table>
                <thead>
                    <tr>
                        <th>Loại giao dịch</th>
                        <th>Số tiền</th>
                        <th>Ngày giao dịch</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($transaction = $transaction_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($transaction['transaction_type']); ?></td>
                            <td><?php echo number_format($transaction['amount'], 2) . " VND"; ?></td>
                            <td><?php echo htmlspecialchars($transaction['transaction_date']); ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p>Không có giao dịch nào được tìm thấy.</p>
        <?php endif; ?>
    </div>
</body>
</html>
