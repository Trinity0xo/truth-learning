package com.truthlearning.truth.leaning.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.nio.charset.StandardCharsets;

@Service
public class MailService {
    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine templateEngine;

    public MailService(JavaMailSender javaMailSender, SpringTemplateEngine templateEngine) {
        this.javaMailSender = javaMailSender;
        this.templateEngine = templateEngine;
    }

    public void sendEmailSync(String to, String subject, String content, boolean isMultipart, boolean isHtml) {
        MimeMessage mimeMessage = this.javaMailSender.createMimeMessage();
        try {
            MimeMessageHelper message = new MimeMessageHelper(mimeMessage, isMultipart, StandardCharsets.UTF_8.name());
            message.setTo(to);
            message.setSubject(subject);
            message.setText(content, isHtml);
            this.javaMailSender.send(mimeMessage);
        } catch (MailException | MessagingException e) {
            System.out.println("error sending email: " + e);
        }
    }

    public void sendEmailFromTemplateSync(
            String to,
            String subject,
            String templateName,
            String username,
            Object value) {

        Context context = new Context();
        context.setVariable("name", username);
        context.setVariable("value", value);

        String content = templateEngine.process(templateName, context);
        this.sendEmailSync(to, subject, content, false, true);
    }

    @Async
    public void handleSendVerifyEmailLink(String username, String email, String verifyEmailToken){
        String verifyLink = "http://localhost:3000/verify-email?token=" + verifyEmailToken;
        this.sendEmailFromTemplateSync(email, "Xác thực tài khoản","/email/verifyEmail", username, verifyLink);
    }

    @Async
    public void handleSendResetPasswordLink(String username, String email, String verifyResetPasswordToken){
        String verifyLink = "http://localhost:3000/reset-password?token=" + verifyResetPasswordToken;
        this.sendEmailFromTemplateSync(email, "Reset mật khẩu","/email/resetPassword", username, verifyLink);
    }
}
