package kz.security_hackathon.group_nine;

import javax.crypto.SecretKey;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Scanner;

public class ClientApp {
    private static final String SERVER_URL = "https://localhost:8443/chat/sendMessage";

    public static void main(String[] args) throws Exception {
        SecretKey secretKey = EncryptionUtil.generateKey();
        Scanner scanner = new Scanner(System.in);
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
                (hostname, sslSession) -> {
                    return hostname.equals("localhost");
                });
        System.out.println("Введите сообщение для отправки (или 'exit' для выхода):");
        try {
            // Путь к папке с сертификатами
            String certsDirPath = "src/main/resources/"; // Папка с сертификатами
            // Путь к вашему хранилищу доверенных сертификатов в resources
            String trustStorePath = "/truststore.jks";
            // Пароль для хранилища
            String trustStorePassword = "AEZAKMI";

            // Загружаем хранилище доверенных сертификатов
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null); // Инициализируем пустое хранилище

            // Загружаем сертификаты из папки
            File certsDir = new File(certsDirPath);
            if (certsDir.exists() && certsDir.isDirectory()) {
                for (File certFile : certsDir.listFiles()) {
                    if (certFile.getName().endsWith(".crt")) { // Проверяем, что это файл сертификата
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        try (FileInputStream fis = new FileInputStream(certFile)) {
                            Certificate cert = cf.generateCertificate(fis);
                            trustStore.setCertificateEntry(certFile.getName(), cert);
                        }
                    }
                }
            } else {
                throw new FileNotFoundException("Папка с сертификатами не найдена.");
            }

            // Настройка SSLContext для использования хранилища доверенных сертификатов
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            // Устанавливаем SSLContext по умолчанию
            SSLContext.setDefault(sslContext);

        } catch (Exception e) {
            e.printStackTrace();
        }

        while (true) {
            String message = scanner.nextLine();
            if ("exit".equalsIgnoreCase(message)) {
                break;
            }

            // Генерация случайного вектора и шифрование сообщения
            byte[] iv = EncryptionUtil.generateIV();
            String encryptedMessage = EncryptionUtil.encrypt(message, secretKey, iv);

            // Отправка зашифрованного сообщения на сервер
            String response = sendMessageToServer(encryptedMessage);
            System.out.println("Ответ от сервера: " + response);

            // Получаем зашифрованное сообщение от сервера (в реальном случае это будет другой запрос)
            // Например, здесь мы просто расшифровываем ранее отправленное сообщение
            String decryptedMessage = EncryptionUtil.decrypt(encryptedMessage, secretKey);
            System.out.println("Расшифрованное сообщение: " + decryptedMessage);
        }

        scanner.close();
    }

    private static String sendMessageToServer(String encryptedMessage) throws Exception {
        URL url = new URL(SERVER_URL + "?clientIP=192.168.0.110");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "text/plain");

        // Отправка зашифрованного сообщения как текст
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = encryptedMessage.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpsURLConnection.HTTP_OK) {
            return "Сообщение успешно отправлено";
        } else {
            return "Ошибка при отправке сообщения: " + responseCode;
        }
    }
}
