package kz.security_hackathon.group_nine;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Objects;

public class SSLUtil {
    public static void setupSSL(String certsDirPath) throws Exception {
        // Загружаем хранилище доверенных сертификатов
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null); // Инициализируем пустое хранилище

        // Загружаем сертификаты из указанной папки
        File certsDir = new File(certsDirPath);
        if (certsDir.exists() && certsDir.isDirectory()) {
            for (File certFile : Objects.requireNonNull(certsDir.listFiles())) {
                if (certFile.getName().endsWith(".crt")) {
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
    }
}
