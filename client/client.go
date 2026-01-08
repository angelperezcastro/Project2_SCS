package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	_ "strings"


	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

//===========================================================================================================
//DATA STRUCTURES
//===========================================================================================================
type User struct {
    Username  string
    SignKey   userlib.DSSignKey  // Clave privada para firmar (invitaciones)
    DecKey    userlib.PKEDecKey  // Clave privada para descifrar (recibir invitaciones)
    SourceKey []byte             // Derivada del password, para derivar otras claves
}

// FileAccess - Puntero a un archivo en el namespace del usuario
// Para owners: contiene las claves directamente
// Para usuarios compartidos: contiene referencia a su invitación para obtener claves actualizadas
type FileAccess struct {
	IsOwner        bool      // Si es true, las claves están aquí; si no, hay que leer la invitación
	FileMetaUUID   uuid.UUID // Dónde está el FileMeta
	SymKey         []byte    // Clave simétrica (solo válida si IsOwner o recién aceptada)
	MacKey         []byte    // Clave para verificar integridad
	InvitationUUID uuid.UUID // UUID de la invitación (para no-owners, para refrescar claves)
	SenderUsername string    // Quién envió la invitación (para verificar firma al refrescar)
}

// FileMeta - Metadata del archivo
type FileMeta struct {
	OwnerUsername  string               // Quién es el dueño
	FirstBlockUUID uuid.UUID            // Primer bloque de contenido
	LastBlockUUID  uuid.UUID            // Último bloque (para append eficiente)
	DirectShares   map[string]uuid.UUID // username -> InvitationUUID
}

// FileBlock - Un bloque de contenido del archivo (linked list)
type FileBlock struct {
	Content  []byte    // El contenido de este bloque
	NextUUID uuid.UUID // Siguiente bloque, uuid.Nil si es el último
}

// Invitation - Información enviada al recipient para darle acceso
type Invitation struct {
	FileMetaUUID uuid.UUID
	SymKey       []byte
	MacKey       []byte
}

// SignedInvitation - Wrapper para invitación cifrada y firmada
type SignedInvitation struct {
	EncryptedData []byte
	Signature     []byte
}

// HybridEncrypted - Estructura para hybrid encryption
// RSA solo puede cifrar ~190 bytes, así que ciframos una clave simétrica con RSA
// y luego ciframos los datos reales con esa clave simétrica
type HybridEncrypted struct {
	EncryptedSymKey []byte // Clave simétrica cifrada con RSA (pequeña)
	EncryptedData   []byte // Datos cifrados con la clave simétrica (sin límite)
}

//===========================================================================================================
//HELPER FUNCTIONS
//===========================================================================================================
// encryptAndMAC - Cifra datos y añade MAC para integridad (encrypt-then-MAC)
func encryptAndMAC(data []byte, encKey []byte, macKey []byte) ([]byte, error) {
	// Generar IV aleatorio para cada cifrado
	iv := userlib.RandomBytes(16)

	// Cifrar (el IV se incluye en el ciphertext)
	ciphertext := userlib.SymEnc(encKey, iv, data)

	// Calcular MAC sobre el ciphertext (encrypt-then-MAC)
	mac, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return nil, err
	}

	// Concatenar: ciphertext || MAC
	result := append(ciphertext, mac...)
	return result, nil
}

// decryptAndVerify - Verifica MAC y descifra datos
func decryptAndVerify(data []byte, encKey []byte, macKey []byte) ([]byte, error) {
	// El MAC tiene 64 bytes (HMAC-SHA512)
	if len(data) < 64 {
		return nil, errors.New("data too short")
	}

	// Separar ciphertext y MAC
	macStart := len(data) - 64
	ciphertext := data[:macStart]
	providedMAC := data[macStart:]

	// Verificar MAC
	expectedMAC, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return nil, err
	}

	if !userlib.HMACEqual(providedMAC, expectedMAC) {
		return nil, errors.New("MAC verification failed")
	}

	// Descifrar
	plaintext := userlib.SymDec(encKey, ciphertext)
	return plaintext, nil
}

// hybridEncrypt - Cifra datos usando hybrid encryption (RSA + AES)
// Esto permite cifrar datos de cualquier tamaño con una clave pública RSA
func hybridEncrypt(publicKey userlib.PKEEncKey, plaintext []byte) ([]byte, error) {
	// 1. Generar clave simétrica aleatoria
	symKey := userlib.RandomBytes(16)

	// 2. Cifrar la clave simétrica con RSA (esto es pequeño, ~16 bytes)
	encryptedSymKey, err := userlib.PKEEnc(publicKey, symKey)
	if err != nil {
		return nil, err
	}

	// 3. Cifrar los datos con la clave simétrica (sin límite de tamaño)
	iv := userlib.RandomBytes(16)
	encryptedData := userlib.SymEnc(symKey, iv, plaintext)

	// 4. Empaquetar todo junto
	hybrid := HybridEncrypted{
		EncryptedSymKey: encryptedSymKey,
		EncryptedData:   encryptedData,
	}

	return json.Marshal(hybrid)
}

// hybridDecrypt - Descifra datos cifrados con hybrid encryption
func hybridDecrypt(privateKey userlib.PKEDecKey, ciphertext []byte) ([]byte, error) {
	// 1. Deserializar la estructura
	var hybrid HybridEncrypted
	err := json.Unmarshal(ciphertext, &hybrid)
	if err != nil {
		return nil, err
	}

	// 2. Descifrar la clave simétrica con RSA
	symKey, err := userlib.PKEDec(privateKey, hybrid.EncryptedSymKey)
	if err != nil {
		return nil, err
	}

	// 3. Descifrar los datos con la clave simétrica
	plaintext := userlib.SymDec(symKey, hybrid.EncryptedData)

	return plaintext, nil
}

// getUserUUID - Calcula el UUID donde se almacena el User struct
func getUserUUID(username string) (uuid.UUID, error) {
	hash := userlib.Hash([]byte(username + "/user"))
	return uuid.FromBytes(hash[:16])
}

// getFileAccessUUID - Calcula el UUID del FileAccess para un usuario y archivo
func getFileAccessUUID(sourceKey []byte, filename string) (uuid.UUID, error) {
	derived, err := userlib.HashKDF(sourceKey, []byte("fileaccess/"+filename))
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.FromBytes(derived[:16])
}

// deriveKeys - Deriva claves de cifrado y MAC desde una clave fuente
func deriveKeys(sourceKey []byte, purpose string) (encKey []byte, macKey []byte, err error) {
	encKeyFull, err := userlib.HashKDF(sourceKey, []byte(purpose+"/enc"))
	if err != nil {
		return nil, nil, err
	}

	macKeyFull, err := userlib.HashKDF(sourceKey, []byte(purpose+"/mac"))
	if err != nil {
		return nil, nil, err
	}

	return encKeyFull[:16], macKeyFull[:16], nil
}

func (userdata *User) refreshAccessKeys(access *FileAccess) error {
	if access.IsOwner {
		return nil // Owner siempre tiene claves actualizadas
	}

	// Cargar la invitación
	signedInvBytes, ok := userlib.DatastoreGet(access.InvitationUUID)
	if !ok {
		return errors.New("invitation no longer exists - access may have been revoked")
	}

	var signedInv SignedInvitation
	err := json.Unmarshal(signedInvBytes, &signedInv)
	if err != nil {
		return errors.New("corrupted invitation data")
	}

	// Verificar firma del sender
	senderVerifyKey, ok := userlib.KeystoreGet(access.SenderUsername + "/ds")
	if !ok {
		return errors.New("sender no longer exists")
	}

	err = userlib.DSVerify(senderVerifyKey, signedInv.EncryptedData, signedInv.Signature)
	if err != nil {
		return errors.New("invalid invitation signature - may have been tampered")
	}

	// Descifrar invitación
	invitationBytes, err := hybridDecrypt(userdata.DecKey, signedInv.EncryptedData)
	if err != nil {
		return errors.New("could not decrypt invitation - access may have been revoked")
	}

	var invitation Invitation
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return errors.New("corrupted invitation")
	}

	// Actualizar claves en el access
	access.FileMetaUUID = invitation.FileMetaUUID
	access.SymKey = invitation.SymKey
	access.MacKey = invitation.MacKey

	return nil
}

// getFileAccess - Obtiene y descifra el FileAccess, refrescando claves si es necesario
func (userdata *User) getFileAccess(filename string) (*FileAccess, uuid.UUID, error) {
	accessUUID, err := getFileAccessUUID(userdata.SourceKey, filename)
	if err != nil {
		return nil, uuid.Nil, err
	}

	encryptedAccess, ok := userlib.DatastoreGet(accessUUID)
	if !ok {
		return nil, uuid.Nil, errors.New("file not found")
	}

	accessEncKey, accessMacKey, err := deriveKeys(userdata.SourceKey, "fileaccess")
	if err != nil {
		return nil, uuid.Nil, err
	}

	accessBytes, err := decryptAndVerify(encryptedAccess, accessEncKey, accessMacKey)
	if err != nil {
		return nil, uuid.Nil, errors.New("file access corrupted")
	}

	var access FileAccess
	err = json.Unmarshal(accessBytes, &access)
	if err != nil {
		return nil, uuid.Nil, err
	}

	// Si no es owner, refrescar claves desde la invitación
	if !access.IsOwner {
		err = userdata.refreshAccessKeys(&access)
		if err != nil {
			return nil, uuid.Nil, err
		}
	}

	return &access, accessUUID, nil
}

// saveFileAccess - Guarda el FileAccess cifrado
func (userdata *User) saveFileAccess(access *FileAccess, accessUUID uuid.UUID) error {
	accessEncKey, accessMacKey, err := deriveKeys(userdata.SourceKey, "fileaccess")
	if err != nil {
		return err
	}

	accessBytes, err := json.Marshal(access)
	if err != nil {
		return err
	}

	encryptedAccess, err := encryptAndMAC(accessBytes, accessEncKey, accessMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(accessUUID, encryptedAccess)
	return nil
}
// NOTE: The following methods have toy (insecure!) implementations.
//===========================================================================================================
//MAIN FUNCTIONS
//===========================================================================================================
// InitUser - Crea un nuevo usuario
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Validar username
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}

	// Verificar que el usuario no existe
	_, alreadyExists := userlib.KeystoreGet(username + "/pke")
	if alreadyExists {
		return nil, errors.New("user already exists")
	}

	// Generar claves RSA para cifrado
	encKey, decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	// Generar claves RSA para firmas
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// Almacenar claves públicas en Keystore
	err = userlib.KeystoreSet(username+"/pke", encKey)
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(username+"/ds", verifyKey)
	if err != nil {
		return nil, err
	}

	// Derivar SourceKey del password
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Crear struct User
	var userdata User
	userdata.Username = username
	userdata.SignKey = signKey
	userdata.DecKey = decKey
	userdata.SourceKey = sourceKey

	// Serializar User
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	// Derivar claves para cifrar User
	userEncKey, userMacKey, err := deriveKeys(sourceKey, "user-struct")
	if err != nil {
		return nil, err
	}

	// Cifrar User
	encryptedUser, err := encryptAndMAC(userBytes, userEncKey, userMacKey)
	if err != nil {
		return nil, err
	}

	// Calcular UUID y guardar
	userUUID, err := getUserUUID(username)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(userUUID, encryptedUser)

	return &userdata, nil
}

// GetUser - Obtiene un usuario existente
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Derivar SourceKey del password
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Derivar claves
	userEncKey, userMacKey, err := deriveKeys(sourceKey, "user-struct")
	if err != nil {
		return nil, err
	}

	// Calcular UUID
	userUUID, err := getUserUUID(username)
	if err != nil {
		return nil, err
	}

	// Obtener datos
	encryptedUser, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("user does not exist")
	}

	// Verificar y descifrar
	userBytes, err := decryptAndVerify(encryptedUser, userEncKey, userMacKey)
	if err != nil {
		return nil, errors.New("invalid credentials or data corrupted")
	}

	// Deserializar
	var userdata User
	err = json.Unmarshal(userBytes, &userdata)
	if err != nil {
		return nil, err
	}

	// Verificar username
	if userdata.Username != username {
		return nil, errors.New("data integrity check failed")
	}

	// Restaurar SourceKey
	userdata.SourceKey = sourceKey

	return &userdata, nil
}

// StoreFile - Almacena un archivo (crea nuevo o sobrescribe)
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Calcular UUID del FileAccess
	accessUUID, err := getFileAccessUUID(userdata.SourceKey, filename)
	if err != nil {
		return err
	}

	// Verificar si el archivo ya existe
	existingData, exists := userlib.DatastoreGet(accessUUID)

	if exists {
		// Sobrescribir archivo existente
		return userdata.overwriteFile(existingData, content)
	} else {
		// Crear nuevo archivo
		return userdata.createNewFile(accessUUID, content)
	}
}


// AppendToFile - Añade contenido al final de un archivo (eficiente)
func (userdata *User) AppendToFile(filename string, content []byte) error {
	access, _, err := userdata.getFileAccess(filename)
	if err != nil {
		return err
	}

	// Obtener FileMeta
	encryptedMeta, ok := userlib.DatastoreGet(access.FileMetaUUID)
	if !ok {
		return errors.New("file metadata not found")
	}

	metaBytes, err := decryptAndVerify(encryptedMeta, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	var meta FileMeta
	err = json.Unmarshal(metaBytes, &meta)
	if err != nil {
		return err
	}

	// Guardar UUID del último bloque actual
	oldLastBlockUUID := meta.LastBlockUUID

	// Cargar último bloque
	encryptedLastBlock, ok := userlib.DatastoreGet(oldLastBlockUUID)
	if !ok {
		return errors.New("last block not found")
	}

	lastBlockBytes, err := decryptAndVerify(encryptedLastBlock, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	var lastBlock FileBlock
	err = json.Unmarshal(lastBlockBytes, &lastBlock)
	if err != nil {
		return err
	}

	// Crear nuevo bloque
	newBlockUUID := uuid.New()

	newBlock := FileBlock{
		Content:  content,
		NextUUID: uuid.Nil,
	}

	newBlockBytes, err := json.Marshal(newBlock)
	if err != nil {
		return err
	}

	encryptedNewBlock, err := encryptAndMAC(newBlockBytes, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	// Actualizar último bloque para que apunte al nuevo
	lastBlock.NextUUID = newBlockUUID

	updatedLastBlockBytes, err := json.Marshal(lastBlock)
	if err != nil {
		return err
	}

	encryptedUpdatedLastBlock, err := encryptAndMAC(updatedLastBlockBytes, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	// Actualizar FileMeta
	meta.LastBlockUUID = newBlockUUID

	updatedMetaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	encryptedUpdatedMeta, err := encryptAndMAC(updatedMetaBytes, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	// Guardar todo
	userlib.DatastoreSet(newBlockUUID, encryptedNewBlock)
	userlib.DatastoreSet(oldLastBlockUUID, encryptedUpdatedLastBlock)
	userlib.DatastoreSet(access.FileMetaUUID, encryptedUpdatedMeta)

	return nil
}

// LoadFile - Carga el contenido de un archivo
func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	access, _, err := userdata.getFileAccess(filename)
	if err != nil {
		return nil, err
	}

	// Obtener FileMeta
	encryptedMeta, ok := userlib.DatastoreGet(access.FileMetaUUID)
	if !ok {
		return nil, errors.New("file metadata not found")
	}

	metaBytes, err := decryptAndVerify(encryptedMeta, access.SymKey, access.MacKey)
	if err != nil {
		return nil, err
	}

	var meta FileMeta
	err = json.Unmarshal(metaBytes, &meta)
	if err != nil {
		return nil, err
	}

	// Recorrer y concatenar bloques
	content = []byte{}
	currentUUID := meta.FirstBlockUUID

	for currentUUID != uuid.Nil {
		encryptedBlock, ok := userlib.DatastoreGet(currentUUID)
		if !ok {
			return nil, errors.New("file block not found")
		}

		blockBytes, err := decryptAndVerify(encryptedBlock, access.SymKey, access.MacKey)
		if err != nil {
			return nil, err
		}

		var block FileBlock
		err = json.Unmarshal(blockBytes, &block)
		if err != nil {
			return nil, err
		}

		content = append(content, block.Content...)
		currentUUID = block.NextUUID
	}

	return content, nil
}

// createNewFile - Crea un archivo nuevo
func (userdata *User) createNewFile(accessUUID uuid.UUID, content []byte) error {
	// Generar claves para el archivo
	fileSymKey := userlib.RandomBytes(16)
	fileMacKey := userlib.RandomBytes(16)

	// Crear bloque de contenido
	block := FileBlock{
		Content:  content,
		NextUUID: uuid.Nil,
	}

	blockUUID := uuid.New()

	blockBytes, err := json.Marshal(block)
	if err != nil {
		return err
	}

	encryptedBlock, err := encryptAndMAC(blockBytes, fileSymKey, fileMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(blockUUID, encryptedBlock)

	// Crear FileMeta
	meta := FileMeta{
		OwnerUsername:  userdata.Username,
		FirstBlockUUID: blockUUID,
		LastBlockUUID:  blockUUID,
		DirectShares:   make(map[string]uuid.UUID),
	}

	metaUUID := uuid.New()

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	encryptedMeta, err := encryptAndMAC(metaBytes, fileSymKey, fileMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(metaUUID, encryptedMeta)

	// Crear FileAccess (como owner)
	access := FileAccess{
		IsOwner:        true,
		FileMetaUUID:   metaUUID,
		SymKey:         fileSymKey,
		MacKey:         fileMacKey,
		InvitationUUID: uuid.Nil,
		SenderUsername: "",
	}

	return userdata.saveFileAccess(&access, accessUUID)
}

// overwriteFile - Sobrescribe un archivo existente
func (userdata *User) overwriteFile(existingAccessData []byte, content []byte) error {
	// Cargar FileAccess
	accessEncKey, accessMacKey, err := deriveKeys(userdata.SourceKey, "fileaccess")
	if err != nil {
		return err
	}

	accessBytes, err := decryptAndVerify(existingAccessData, accessEncKey, accessMacKey)
	if err != nil {
		return err
	}

	var access FileAccess
	err = json.Unmarshal(accessBytes, &access)
	if err != nil {
		return err
	}

	// Si no es owner, refrescar claves
	if !access.IsOwner {
		err = userdata.refreshAccessKeys(&access)
		if err != nil {
			return err
		}
	}

	// Cargar FileMeta
	encryptedMeta, ok := userlib.DatastoreGet(access.FileMetaUUID)
	if !ok {
		return errors.New("file metadata not found")
	}

	metaBytes, err := decryptAndVerify(encryptedMeta, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	var meta FileMeta
	err = json.Unmarshal(metaBytes, &meta)
	if err != nil {
		return err
	}

	// Eliminar bloques antiguos
	currentUUID := meta.FirstBlockUUID
	for currentUUID != uuid.Nil {
		encryptedBlock, ok := userlib.DatastoreGet(currentUUID)
		if !ok {
			break
		}

		blockBytes, err := decryptAndVerify(encryptedBlock, access.SymKey, access.MacKey)
		if err != nil {
			break
		}

		var block FileBlock
		err = json.Unmarshal(blockBytes, &block)
		if err != nil {
			break
		}

		nextUUID := block.NextUUID
		userlib.DatastoreDelete(currentUUID)
		currentUUID = nextUUID
	}

	// Crear nuevo bloque
	newBlock := FileBlock{
		Content:  content,
		NextUUID: uuid.Nil,
	}

	newBlockUUID := uuid.New()

	newBlockBytes, err := json.Marshal(newBlock)
	if err != nil {
		return err
	}

	encryptedNewBlock, err := encryptAndMAC(newBlockBytes, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(newBlockUUID, encryptedNewBlock)

	// Actualizar FileMeta
	meta.FirstBlockUUID = newBlockUUID
	meta.LastBlockUUID = newBlockUUID

	updatedMetaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	encryptedUpdatedMeta, err := encryptAndMAC(updatedMetaBytes, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(access.FileMetaUUID, encryptedUpdatedMeta)

	return nil
}

// CreateInvitation - Crea una invitación para compartir un archivo
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Verificar que recipient existe
	recipientEncKey, ok := userlib.KeystoreGet(recipientUsername + "/pke")
	if !ok {
		return uuid.Nil, errors.New("recipient user does not exist")
	}

	// Obtener acceso al archivo
	access, _, err := userdata.getFileAccess(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Cargar FileMeta
	encryptedMeta, ok := userlib.DatastoreGet(access.FileMetaUUID)
	if !ok {
		return uuid.Nil, errors.New("file metadata not found")
	}

	metaBytes, err := decryptAndVerify(encryptedMeta, access.SymKey, access.MacKey)
	if err != nil {
		return uuid.Nil, err
	}

	var meta FileMeta
	err = json.Unmarshal(metaBytes, &meta)
	if err != nil {
		return uuid.Nil, err
	}

	// Crear Invitation
	invitation := Invitation{
		FileMetaUUID: access.FileMetaUUID,
		SymKey:       access.SymKey,
		MacKey:       access.MacKey,
	}

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}

	// Cifrar con HYBRID ENCRYPTION (soluciona el problema de RSA message too long)
	encryptedInvitation, err := hybridEncrypt(recipientEncKey, invitationBytes)
	if err != nil {
		return uuid.Nil, err
	}

	// Firmar
	signature, err := userlib.DSSign(userdata.SignKey, encryptedInvitation)
	if err != nil {
		return uuid.Nil, err
	}

	// Empaquetar
	signedInv := SignedInvitation{
		EncryptedData: encryptedInvitation,
		Signature:     signature,
	}

	signedInvBytes, err := json.Marshal(signedInv)
	if err != nil {
		return uuid.Nil, err
	}

	invitationUUID := uuid.New()
	userlib.DatastoreSet(invitationUUID, signedInvBytes)

	// Registrar en DirectShares si somos owner
	if meta.OwnerUsername == userdata.Username {
		meta.DirectShares[recipientUsername] = invitationUUID

		updatedMetaBytes, err := json.Marshal(meta)
		if err != nil {
			return uuid.Nil, err
		}

		encryptedUpdatedMeta, err := encryptAndMAC(updatedMetaBytes, access.SymKey, access.MacKey)
		if err != nil {
			return uuid.Nil, err
		}

		userlib.DatastoreSet(access.FileMetaUUID, encryptedUpdatedMeta)
	}

	return invitationUUID, nil
}

// AcceptInvitation - Acepta una invitación para acceder a un archivo
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Verificar que filename no existe ya
	accessUUID, err := getFileAccessUUID(userdata.SourceKey, filename)
	if err != nil {
		return err
	}

	_, exists := userlib.DatastoreGet(accessUUID)
	if exists {
		return errors.New("filename already exists")
	}

	// Obtener clave de verificación del sender
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "/ds")
	if !ok {
		return errors.New("sender does not exist")
	}

	// Cargar invitación
	signedInvBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation not found")
	}

	var signedInv SignedInvitation
	err = json.Unmarshal(signedInvBytes, &signedInv)
	if err != nil {
		return err
	}

	// Verificar firma
	err = userlib.DSVerify(senderVerifyKey, signedInv.EncryptedData, signedInv.Signature)
	if err != nil {
		return errors.New("invalid signature")
	}

	// Descifrar invitación con HYBRID DECRYPTION
	invitationBytes, err := hybridDecrypt(userdata.DecKey, signedInv.EncryptedData)
	if err != nil {
		return errors.New("could not decrypt invitation")
	}

	var invitation Invitation
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return err
	}

	// Verificar que la invitación es válida
	encryptedMeta, ok := userlib.DatastoreGet(invitation.FileMetaUUID)
	if !ok {
		return errors.New("file no longer exists")
	}

	_, err = decryptAndVerify(encryptedMeta, invitation.SymKey, invitation.MacKey)
	if err != nil {
		return errors.New("access has been revoked")
	}

		// Crear FileAccess local (como no-owner)
	access := FileAccess{
		IsOwner:        false,
		FileMetaUUID:   invitation.FileMetaUUID,
		SymKey:         invitation.SymKey,
		MacKey:         invitation.MacKey,
		InvitationUUID: invitationPtr,
		SenderUsername: senderUsername,
	}

	return userdata.saveFileAccess(&access, accessUUID)
}

// RevokeAccess - Revoca el acceso de un usuario a un archivo
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Obtener acceso al archivo
	access, accessUUID, err := userdata.getFileAccess(filename)
	if err != nil {
		return err
	}

	// Cargar FileMeta
	encryptedMeta, ok := userlib.DatastoreGet(access.FileMetaUUID)
	if !ok {
		return errors.New("file metadata not found")
	}

	metaBytes, err := decryptAndVerify(encryptedMeta, access.SymKey, access.MacKey)
	if err != nil {
		return err
	}

	var meta FileMeta
	err = json.Unmarshal(metaBytes, &meta)
	if err != nil {
		return err
	}

	// Verificar que somos owner
	if meta.OwnerUsername != userdata.Username {
		return errors.New("only the owner can revoke access")
	}

	// Verificar que recipient tiene acceso
	_, hasAccess := meta.DirectShares[recipientUsername]
	if !hasAccess {
		return errors.New("user does not have access")
	}

	// Generar nuevas claves
	newSymKey := userlib.RandomBytes(16)
	newMacKey := userlib.RandomBytes(16)

	oldSymKey := access.SymKey
	oldMacKey := access.MacKey

	// Re-cifrar todos los bloques
	currentUUID := meta.FirstBlockUUID
	for currentUUID != uuid.Nil {
		encryptedBlock, ok := userlib.DatastoreGet(currentUUID)
		if !ok {
			return errors.New("block not found")
		}

		blockBytes, err := decryptAndVerify(encryptedBlock, oldSymKey, oldMacKey)
		if err != nil {
			return err
		}

		var block FileBlock
		err = json.Unmarshal(blockBytes, &block)
		if err != nil {
			return err
		}

		reEncryptedBlock, err := encryptAndMAC(blockBytes, newSymKey, newMacKey)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(currentUUID, reEncryptedBlock)

		currentUUID = block.NextUUID
	}

	// Eliminar invitación del recipient
	invUUID := meta.DirectShares[recipientUsername]
	userlib.DatastoreDelete(invUUID)
	delete(meta.DirectShares, recipientUsername)

	// Actualizar invitaciones de usuarios restantes
	for username, invUUID := range meta.DirectShares {
		userEncKey, ok := userlib.KeystoreGet(username + "/pke")
		if !ok {
			continue
		}

		newInvitation := Invitation{
			FileMetaUUID: access.FileMetaUUID,
			SymKey:       newSymKey,
			MacKey:       newMacKey,
		}

		invitationBytes, err := json.Marshal(newInvitation)
		if err != nil {
			return err
		}

		// Usar hybrid encryption aquí también
		encryptedInvitation, err := hybridEncrypt(userEncKey, invitationBytes)
		if err != nil {
			return err
		}

		signature, err := userlib.DSSign(userdata.SignKey, encryptedInvitation)
		if err != nil {
			return err
		}

		signedInv := SignedInvitation{
			EncryptedData: encryptedInvitation,
			Signature:     signature,
		}

		signedInvBytes, err := json.Marshal(signedInv)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(invUUID, signedInvBytes)
	}

	// Re-cifrar FileMeta
	updatedMetaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	encryptedUpdatedMeta, err := encryptAndMAC(updatedMetaBytes, newSymKey, newMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(access.FileMetaUUID, encryptedUpdatedMeta)

	// Actualizar nuestro FileAccess
	access.SymKey = newSymKey
	access.MacKey = newMacKey

	updatedAccessBytes, err := json.Marshal(access)
	if err != nil {
		return err
	}

	encryptedUpdatedAccess, err := encryptAndMAC(updatedAccessBytes, accessEncKey, accessMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(accessUUID, encryptedUpdatedAccess)

	return nil
}
