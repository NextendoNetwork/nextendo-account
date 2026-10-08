package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func signeStripe(secret string, t int64, corps []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(t, 10) + "."))
	mac.Write(corps)
	return "t=" + strconv.FormatInt(t, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestSignatureStripe(t *testing.T) {
	secret := "whsec_test"
	corps := []byte(`{"type":"checkout.session.completed"}`)
	now := time.Unix(1791380000, 0)
	bonne := signeStripe(secret, now.Unix(), corps)

	if !signatureStripeValide(bonne, corps, secret, now) {
		t.Fatal("une signature valide est refusee")
	}
	cas := map[string]bool{
		"corps modifie":       signatureStripeValide(bonne, []byte(`{"type":"autre"}`), secret, now),
		"mauvais secret":      signatureStripeValide(bonne, corps, "whsec_autre", now),
		"secret vide":         signatureStripeValide(bonne, corps, "", now),
		"entete vide":         signatureStripeValide("", corps, secret, now),
		"sans v1":             signatureStripeValide("t="+strconv.FormatInt(now.Unix(), 10), corps, secret, now),
		"rejoue 10 min apres": signatureStripeValide(bonne, corps, secret, now.Add(10*time.Minute)),
		"horodatage futur":    signatureStripeValide(signeStripe(secret, now.Unix()+900, corps), corps, secret, now),
		"signature tronquee":  signatureStripeValide(bonne[:len(bonne)-4], corps, secret, now),
	}
	for nom, accepte := range cas {
		if accepte {
			t.Errorf("%s : accepte alors que ca doit etre refuse", nom)
		}
	}
	// Stripe peut envoyer plusieurs v1 (rotation de secret) : une seule bonne suffit.
	if !signatureStripeValide(bonne+",v1=00ff", corps, secret, now) {
		t.Error("plusieurs v1 : la bonne n'est pas reconnue")
	}
}
