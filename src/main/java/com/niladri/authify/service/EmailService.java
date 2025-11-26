package com.niladri.authify.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {

  private final JavaMailSender javaMailSender;

  @Value("${spring.mail.properties.mail.smtp.from:senniladri007@gmail.com}")
  private String sendMailFrom;

  public void sendEmail(String to) {
    SimpleMailMessage mailMessage = new SimpleMailMessage();
    mailMessage.setFrom(sendMailFrom);
    mailMessage.setTo(to);
    mailMessage.setSubject("Welcome to Authify");
    mailMessage.setText("Hello " + to + "\n\n" + "You have successfully registered to Authify");
    javaMailSender.send(mailMessage);
  }

  public void sendResetOtpEmail(String to, String otp) {
    SimpleMailMessage mailMessage = new SimpleMailMessage();
    mailMessage.setFrom(sendMailFrom);
    mailMessage.setTo(to);
    mailMessage.setSubject("Authify Password Reset OTP");
    mailMessage.setText("Hello " + to + "\n\n" + "Your OTP for password reset is: " + otp + "\n\n" + "This OTP is valid for 10 minutes.");
    javaMailSender.send(mailMessage);
  }


        public void sendOtpEmail(String toEmail, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(sendMailFrom);
        message.setTo(toEmail);
        message.setSubject("Account Verification OTP");
        message.setText("Your OTP is "+otp+". Verify your account using this OTP.");
        javaMailSender.send(message);
    }
}
