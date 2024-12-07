package kz.security_hackathon.group_nine;

import javax.crypto.SecretKey;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Scanner;
import javax.net.ssl.HttpsURLConnection;

public class ClientApp {
    private static final String SERVER_URL = "https://localhost:8443/chat/sendMessage";
    private static final String EXPECTED_HOST = "localhost";

    public static void main(String[] args) throws Exception {
        // Генерация секретного ключа
        SecretKey secretKey = EncryptionUtil.generateKey();

        // Настройка SSL (папка с сертификатами)
        SSLUtil.setupSSL("src/main/resources/");

        // Установка HostnameVerifier
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, sslSession) -> hostname.equals(EXPECTED_HOST));

        // Работа с пользователем
        Scanner scanner = new Scanner(System.in);
        System.out.println("Введите сообщение для отправки (или 'exit' для выхода):");

        while (true) {
            String message = scanner.nextLine();
            if ("exit".equalsIgnoreCase(message)) {
                break;
            }

            // Шифрование сообщения
            byte[] iv = EncryptionUtil.generateIV();
            String encryptedMessage = EncryptionUtil.encrypt(message, secretKey, iv);

            // Отправка сообщения на сервер
            String response = sendMessageToServer(encryptedMessage);
            System.out.println("Ответ от сервера: " + response);
        }

        scanner.close();
    }

    private static String sendMessageToServer(String encryptedMessage) throws Exception {
        URL url = new URL(SERVER_URL + "?clientIP=192.168.0.110");
        String host = url.getHost();
        if (!host.equals(EXPECTED_HOST)) {
            throw new UnknownHostException("Неверный хост: " + host + ". Ожидается: " + EXPECTED_HOST);
        }

        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "text/plain");

        // Отправка сообщения
        try (var os = connection.getOutputStream()) {
            os.write(encryptedMessage.getBytes("utf-8"));
        }

        int responseCode = connection.getResponseCode();
        return (responseCode == HttpsURLConnection.HTTP_OK)
                ? "Сообщение успешно отправлено"
                : "Ошибка при отправке сообщения: " + responseCode;
    }
}
