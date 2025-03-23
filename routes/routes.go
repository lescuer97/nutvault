package routes

import (
	"fmt"
	"nutmix_remote_signer/signer"

	"github.com/gin-gonic/gin"
	"github.com/lescuer97/nutmix/api/cashu"
)


func Routes(r *gin.Engine, signer signer.Signer) {
	r.GET("/keys", func(c *gin.Context) {

		keys, err := signer.GetActiveKeys()
		if err != nil {
			// logger.Error(fmt.Sprintf("mint.Signer.GetActiveKeys() %+v ", err))
			c.JSON(400, cashu.ErrorCodeToResponse(cashu.KEYSET_NOT_KNOW, nil))
			return
		}

		c.JSON(200, keys)

	})

	r.GET("/keys/:id", func(c *gin.Context) {

		id := c.Param("id")
		keysets, err := signer.GetKeysById(id)

		if err != nil {
			// logger.Error(fmt.Sprintf("mint.Signer.GetKeysById(id) %+v", err))
			c.JSON(400, cashu.ErrorCodeToResponse(cashu.KEYSET_NOT_KNOW, nil))
			return
		}

		c.JSON(200, keysets)

	})
	r.GET("/keysets", func(c *gin.Context) {
		keys, err := signer.GetKeys()
		if err != nil {
			c.Error(fmt.Errorf("signer.GetKeys(). %w", err))
			c.JSON(500, "Server side error")
			return
		}

		c.JSON(200, keys)
	})

	r.POST("/blind_sign", func(c *gin.Context) {

		var messages []cashu.BlindedMessage
		err := c.ShouldBindJSON(&messages)
		if err != nil {
			c.Error(fmt.Errorf("c.ShouldBindJSON(&messages). %w", err))
			c.JSON(400, "Malformed body request")
			return
		}
		_, recoverySig,  err := signer.SignBlindMessages(messages)
		if err != nil {
			c.Error(fmt.Errorf("signer.GetKeys(). %w", err))
			c.JSON(500, "Server side error")
			return
		}

		c.JSON(200, recoverySig)
	})
	r.POST("/verify_proofs", func(c *gin.Context) {
		var proofs cashu.Proofs
		err := c.ShouldBindJSON(&proofs)
		if err != nil {
			c.Error(fmt.Errorf("c.ShouldBindJSON(&proofs). %w", err))
			c.JSON(400, "Malformed body request")
			return
		}

		keys, err := signer.GetKeys()
		if err != nil {
			c.Error(fmt.Errorf("signer.GetKeys(). %w", err))
			c.JSON(500, "Server side error")
			return
		}

		c.JSON(200, keys)
	})

	r.GET("/pubkey", func(c *gin.Context) {
		pubkey, err := signer.GetSignerPubkey()
		if err != nil {
			c.Error(fmt.Errorf("signer.GetSignerPubkey(). %w", err))
			c.JSON(500, "Server side error")
			return
		}

		c.JSON(200, pubkey)
	})
	r.GET("/ping", func(c *gin.Context) {
		var ping string
		err := c.Bind(ping)
		if err != nil {
			c.Error(fmt.Errorf("c.Bind(ping). %w", err))
			c.JSON(403, "Incorrect ping")
			return
		}

		c.String(200, "pong")
	})
}
