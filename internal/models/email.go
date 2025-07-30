package models

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
)

type Mail struct {
	Recipient []string
	Message   []byte
	//Subject   	string
}

func NewMail(message string, recipient []string) *Mail {
	return &Mail{
		Recipient: recipient,
		Message:   []byte(message),
	}
}

// SendEmail envoie un e-mail via SMTP en utilisant STARTTLS sur le port 587.
func (s *Mail) SendEmail() error {
	from := os.Getenv("EMAIL_ADDRESS")
	password := os.Getenv("PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("PORT")

	message := []byte(
		"From: " + from + "\r\n" +
		"To: " + s.Recipient[0] + "\r\n" + 
		"Subject: Email Verification\r\n" +
		"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n" + // Exemple pour du HTML
		"\r\n" + // Ligne vide séparant les en-têtes du corps
		string(s.Message) + "\r\n")

	// Configuration TLS pour StartTLS
	// InsecureSkipVerify: true est à utiliser avec PRUDENCE en production.
	// Il désactive la vérification du certificat du serveur, ce qui est une faille de sécurité.
	// Pour la production, assurez-vous que le certificat est valide et supprimez cette ligne.
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true, // À désactiver en production après validation du certificat
		ServerName:         smtpHost,
	}

	// Établir une connexion SMTP non chiffrée initialement
	// smtp.Dial gère la connexion TCP et la salutation initiale (EHLO).
	client, err := smtp.Dial(smtpHost+":"+smtpPort)
	if err != nil {
		return fmt.Errorf("failed to dial SMTP server: %v", err)
	}
	defer client.Quit() // Assure que la connexion est fermée proprement à la fin

	// Passer à une connexion TLS chiffrée (STARTTLS)
	if err = client.StartTLS(tlsconfig); err != nil {
		return fmt.Errorf("failed to start TLS: %v", err)
	}

	// Authentification après le chiffrement
	auth := smtp.PlainAuth("", from, password, smtpHost)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	// Définir l'expéditeur
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %v", err)
	}

	// Définir les destinataires
	for _, recipient := range s.Recipient {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient: %v", err)
		}
	}

	// Obtenir un writer pour le corps du message
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %v", err)
	}
	defer writer.Close() // Ferme le writer et envoie le message

	// Écrire le message
	if _, err := writer.Write(message); err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}

	return nil
}
