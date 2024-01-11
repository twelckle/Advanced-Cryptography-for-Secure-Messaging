//Theo Welckle
//Tlw9927

// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	//"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
	ChangeRoot		  bool
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	sesh := c.Sessions[*partnerIdentity];
	for key, _ := range sesh.CachedReceiveKeys{
		sesh.CachedReceiveKeys[key].Zeroize();
	}
	sesh.MyDHRatchet.Zeroize();
	sesh.RootChain.Zeroize();
	sesh.SendChain.Zeroize();
	sesh.ReceiveChain.Zeroize();

	delete(c.Sessions, *partnerIdentity)
	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	//have to create a session for the new partner
	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet: GenerateKeyPair(),
		SendCounter: 0,
		ReceiveCounter: 0,
		LastUpdate: 0,
		ChangeRoot: false,
	}

	ephermeralKey := c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey;

	return &(ephermeralKey), nil;
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet: GenerateKeyPair(),
		PartnerDHRatchet: partnerEphemeral,
		SendCounter: 0,
		ReceiveCounter: 0,
		LastUpdate: 0,
		ChangeRoot: true,
	}

	// TODO: your code here
	bobEphermeralKey := c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey;
	//ga is given as Alice public key. We combine this with session private key from Bob
	gab := DHCombine(partnerEphemeral, &(c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey))

	//gA is given to us through partner Identity. We combine this with bobs private b
	gAb := DHCombine(partnerIdentity, &(c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey))

	//ga is given as Alice public key. We combine this with private key from Bob
	gaB := DHCombine(partnerEphemeral, &(c.Identity.PrivateKey))



	
	keyRoot := CombineKeys(gAb, gaB, gab) 
	c.Sessions[*partnerIdentity].RootChain = keyRoot;
	c.Sessions[*partnerIdentity].SendChain = keyRoot;
	c.Sessions[*partnerIdentity].ReceiveChain = keyRoot;

	gaB.Zeroize()
	gAb.Zeroize()
	gab.Zeroize()

	return &(bobEphermeralKey), keyRoot.DeriveKey(HANDSHAKE_CHECK_LABEL), nil;
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	// TODO: your code here
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral;

	//gb is given as Bob public key. We combine this with session private key from Alice
	gab := DHCombine(partnerEphemeral, &(c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey))

	//gb is given as Bob's public key. We combine this with private key from Aplice
	gAb := DHCombine(partnerEphemeral, &(c.Identity.PrivateKey))

	//gB is given as . We combine this with private session key of Alice
	gaB := DHCombine(partnerIdentity, &(c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey))

	keyRoot := CombineKeys(gAb, gaB, gab);
	c.Sessions[*partnerIdentity].RootChain = keyRoot;
	c.Sessions[*partnerIdentity].SendChain = keyRoot;
	c.Sessions[*partnerIdentity].ReceiveChain = keyRoot;

	gaB.Zeroize()
	gAb.Zeroize()
	gab.Zeroize()

	return keyRoot.DeriveKey(HANDSHAKE_CHECK_LABEL), nil;

}

func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		IV: NewIV(),
		Counter: 0,
		LastUpdate: 0,
	}

	sesh := c.Sessions[*partnerIdentity];


	
	if(sesh.ChangeRoot){
		//create new Rootkey
		chainKey := sesh.RootChain.DeriveKey(ROOT_LABEL);
		defer chainKey.Zeroize();
		defer sesh.MyDHRatchet.Zeroize();
		sesh.MyDHRatchet = GenerateKeyPair();
		nextRootKey := DHCombine(sesh.PartnerDHRatchet, &sesh.MyDHRatchet.PrivateKey);
		defer nextRootKey.Zeroize();

		//If rootchain isn't recievechain then I should defer delete
		if(sesh.RootChain != sesh.ReceiveChain){
			defer sesh.RootChain.Zeroize();
		}
		sesh.RootChain = CombineKeys(chainKey,nextRootKey);

		//update the session to reflect this new Root
		sesh.ChangeRoot = false;
		if(sesh.SendChain != sesh.ReceiveChain){
			defer sesh.SendChain.Zeroize();
		}
		sesh.SendChain = sesh.RootChain;
		sesh.LastUpdate = sesh.SendCounter+1;
	}

	//ratchet
	if(sesh.SendChain != sesh.RootChain && sesh.SendChain != sesh.ReceiveChain){
		defer sesh.SendChain.Zeroize();
	}
	sesh.SendChain = sesh.SendChain.DeriveKey(CHAIN_LABEL)
	messageKey := sesh.SendChain.DeriveKey(KEY_LABEL)
	defer messageKey.Zeroize();


	//update message variables
	sesh.SendCounter++;
	message.Counter = sesh.SendCounter;
	message.LastUpdate = sesh.LastUpdate;
	message.NextDHRatchet = &sesh.MyDHRatchet.PublicKey;

	//encode
	extraData := message.EncodeAdditionalData();
	message.Ciphertext = messageKey.AuthenticatedEncrypt(plaintext, extraData, message.IV);


	return message, nil
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	sesh := c.Sessions[*message.Sender];

	//creating backup if message authentication fails
	oldCachedReceiveKeys := make(map[int]*SymmetricKey);
	for key, value := range sesh.CachedReceiveKeys{
		oldCachedReceiveKeys[key] = value.Duplicate();
	}
	oldReceiveChain := sesh.ReceiveChain.Duplicate();
	oldRootChain := sesh.RootChain.Duplicate();
	oldDHRatchet := sesh.PartnerDHRatchet.Duplicate();
	oldReceiveCounter := sesh.ReceiveCounter;
	oldLastUpdate := sesh.LastUpdate;
	oldChangeRoot := sesh.ChangeRoot;
	
	//If message counter smaller then the greatest message already received
		//ONE: If the key is available in the cached table use that key to decrypt message
		//TWO: If key doens't exist then the message is either 1) tampered with or 2) being replayed --> raise error 
	if message.Counter <= sesh.ReceiveCounter {
		if messageKey, exists := sesh.CachedReceiveKeys[message.Counter]; exists {
			extraData := message.EncodeAdditionalData();
			plainText, plainTextError := messageKey.AuthenticatedDecrypt(message.Ciphertext, extraData, message.IV);
			messageKey.Zeroize()
			delete(sesh.CachedReceiveKeys, message.Counter);
			
			//If an error is raised during Decrypt meaning the message has been tampered with then restore to original
			if(plainTextError != nil){
				for key, _ := range sesh.CachedReceiveKeys{
					sesh.CachedReceiveKeys[key].Zeroize();
				}
				sesh.CachedReceiveKeys = oldCachedReceiveKeys
				sesh.ReceiveChain.Zeroize();
				sesh.ReceiveChain = oldReceiveChain
				sesh.RootChain.Zeroize();
				sesh.RootChain = oldRootChain;
				sesh.PartnerDHRatchet = oldDHRatchet
				sesh.LastUpdate = oldLastUpdate
				sesh.ReceiveCounter = oldReceiveCounter
				sesh.ChangeRoot = oldChangeRoot
			//If no error is raised then we must zeroize the backup keys
			}else{
				for key, _ := range oldCachedReceiveKeys{
					oldCachedReceiveKeys[key].Zeroize();
				}
				oldReceiveChain.Zeroize();
				oldRootChain.Zeroize();
			}
			return plainText, plainTextError
		}else{
			return "", errors.New("Can't replay messages")
		}
	}

	sameRoot := bytes.Equal(sesh.PartnerDHRatchet.Fingerprint(), message.NextDHRatchet.Fingerprint());

	//Either the root has changed or it hasn't
	if(!sameRoot){

		//if the message is way ahead then we need to track the keys that came from the previous root
		for(sesh.ReceiveCounter < message.LastUpdate - 1){
			sesh.ReceiveCounter++;
			if(sesh.ReceiveChain != sesh.SendChain){
				defer sesh.ReceiveChain.Zeroize();
			}
			sesh.ReceiveChain = sesh.ReceiveChain.DeriveKey(CHAIN_LABEL)
			messageKey := sesh.ReceiveChain.DeriveKey(KEY_LABEL)
			sesh.CachedReceiveKeys[sesh.ReceiveCounter] = messageKey;
		}

		//change the root
		sesh.ChangeRoot = true;
		chainKey := sesh.RootChain.DeriveKey(ROOT_LABEL);
		defer chainKey.Zeroize();
		nextRootKey := DHCombine(message.NextDHRatchet, &sesh.MyDHRatchet.PrivateKey);
		defer nextRootKey.Zeroize();
		
		if(sesh.RootChain != sesh.SendChain){
			defer sesh.RootChain.Zeroize();
			defer sesh.ReceiveChain.Zeroize();
		}
		sesh.RootChain = CombineKeys(chainKey,nextRootKey);
		sesh.ReceiveChain = sesh.RootChain;
		sesh.PartnerDHRatchet = message.NextDHRatchet;
		sesh.LastUpdate = message.LastUpdate;

		//if the counter for the message is further along then when the root changed we need to store the intermediate keys
		for(sesh.ReceiveCounter < message.Counter){
			sesh.ReceiveCounter++;
			if(sesh.ReceiveChain != sesh.RootChain){
				defer sesh.ReceiveChain.Zeroize();
			}
			sesh.ReceiveChain = sesh.ReceiveChain.DeriveKey(CHAIN_LABEL)
			messageKey := sesh.ReceiveChain.DeriveKey(KEY_LABEL)
			sesh.CachedReceiveKeys[sesh.ReceiveCounter] = messageKey;
		}
	//if message uses the sameRoot as before
	} else {
		//store all messages that may come before and the message.Counter
		for(sesh.ReceiveCounter < message.Counter){
			sesh.ReceiveCounter++;
			if(sesh.ReceiveChain != sesh.RootChain && sesh.ReceiveChain != sesh.SendChain){
				defer sesh.ReceiveChain.Zeroize();
			}
			sesh.ReceiveChain = sesh.ReceiveChain.DeriveKey(CHAIN_LABEL)
			messageKey := sesh.ReceiveChain.DeriveKey(KEY_LABEL)
			sesh.CachedReceiveKeys[sesh.ReceiveCounter] = messageKey;
		}
		
	} 

	//only way for the message to reach here is if the key has just been created
	messageKey, _ := sesh.CachedReceiveKeys[message.Counter]
	extraData := message.EncodeAdditionalData();
	plainText, plainTextError := messageKey.AuthenticatedDecrypt(message.Ciphertext, extraData, message.IV);
	messageKey.Zeroize()
	delete(sesh.CachedReceiveKeys, message.Counter);

	if(plainTextError != nil){
		for key, _ := range sesh.CachedReceiveKeys{
			sesh.CachedReceiveKeys[key].Zeroize();
		}
		sesh.CachedReceiveKeys = oldCachedReceiveKeys
		defer sesh.ReceiveChain.Zeroize();
		sesh.ReceiveChain = oldReceiveChain
		defer sesh.RootChain.Zeroize();
		sesh.RootChain = oldRootChain;
		sesh.PartnerDHRatchet = oldDHRatchet
		sesh.LastUpdate = oldLastUpdate
		sesh.ReceiveCounter = oldReceiveCounter
		sesh.ChangeRoot = oldChangeRoot
	}else{
		for key, _ := range oldCachedReceiveKeys{
			oldCachedReceiveKeys[key].Zeroize();
		}
		oldReceiveChain.Zeroize();
		oldRootChain.Zeroize();
	}

	return plainText, plainTextError;

}


