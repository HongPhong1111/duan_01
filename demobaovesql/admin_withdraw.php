<!-- admin_withdraw.php -->
<h2>Rút tiền từ tài khoản người dùng</h2>
<form action="admin_withdraw_handler.php" method="post">
    <label for="user_id">Chọn người dùng:</label><br>
    <select id="user_id" name="user_id">
        <?php
        // Lấy danh sách tất cả người dùng
        include 'db_connection.php';
        $query = "SELECT id, username FROM users";
        $result = $conn->query($query);

        while ($row = $result->fetch_assoc()) {
            echo "<option value='" . $row['id'] . "'>" . $row['username'] . "</option>";
        }
        ?>
    </select><br><br>

    <label for="amount">Số tiền cần rút:</label><br>
    <input type="number" id="amount" name="amount" step="0.01" required><br><br>
    <input type="submit" value="Rút tiền">
</form>
