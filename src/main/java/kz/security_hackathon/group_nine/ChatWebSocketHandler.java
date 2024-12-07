package kz.security_hackathon.group_nine;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.springframework.web.socket.TextMessage;

import javax.crypto.SecretKey;

@Component
public class ChatWebSocketHandler extends TextWebSocketHandler {
    private final SecretKey secretKey;

    public ChatWebSocketHandler(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String encryptedMessage = message.getPayload();
        System.out.println("Получено сообщение от клиента: " + encryptedMessage);

        // Расшифровываем сообщение
        String decryptedMessage = EncryptionUtil.decrypt(encryptedMessage, secretKey);
        System.out.println("Расшифрованное сообщение: " + decryptedMessage);

        // Отправляем ответ обратно клиенту
        String response = "Сервер получил ваше сообщение: " + decryptedMessage;
        String encryptedResponse = EncryptionUtil.encrypt(response, secretKey, EncryptionUtil.generateIV());
        session.sendMessage(new TextMessage(encryptedResponse));
    }
}
