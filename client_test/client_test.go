package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// Helper function to measure bandwidth of a particular operation
func measureBandwidth(probe func()) int {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}

// ================================================
// Global Variables
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

var _ = Describe("Client Tests", func() {

	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	//var eve *client.User

	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	// ================================================
	// BASIC TESTS (los que ya vienen)
	// ================================================
	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	// ================================================
	// USER TESTS - Errores de InitUser y GetUser
	// ================================================
	Describe("User Authentication Tests", func() {

		Specify("Test: Empty username should fail", func() {
			userlib.DebugMsg("Attempting to create user with empty username")
			_, err := client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Duplicate username should fail", func() {
			userlib.DebugMsg("Creating first user alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to create duplicate user alice")
			_, err = client.InitUser("alice", "differentpassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Wrong password should fail", func() {
			userlib.DebugMsg("Creating user alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to get alice with wrong password")
			_, err = client.GetUser("alice", "wrongpassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Get non-existent user should fail", func() {
			userlib.DebugMsg("Attempting to get non-existent user")
			_, err := client.GetUser("nonexistent", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Empty password should work", func() {
			userlib.DebugMsg("Creating user with empty password")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user with empty password")
			aliceLaptop, err = client.GetUser("alice", "")
			Expect(err).To(BeNil())
		})

		Specify("Test: Case sensitive usernames", func() {
			userlib.DebugMsg("Creating user Alice (capital A)")
			_, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating user alice (lowercase a)")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Both should be different users")
		})

		Specify("Test: Same password for different users", func() {
			userlib.DebugMsg("Creating alice with password")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating bob with same password")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Both should work independently")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

	})

	// ================================================
	// FILE TESTS - Errores de Store/Load/Append
	// ================================================
	Describe("File Operation Tests", func() {

		Specify("Test: Load non-existent file should fail", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to load non-existent file")
			_, err = alice.LoadFile("nonexistent.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Append to non-existent file should fail", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to append to non-existent file")
			err = alice.AppendToFile("nonexistent.txt", []byte("data"))
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Empty filename should work", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file with empty filename")
			err = alice.StoreFile("", []byte("content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file with empty filename")
			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content")))
		})

		Specify("Test: Empty content should work", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file with empty content")
			err = alice.StoreFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file with empty content")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("")))
		})

		Specify("Test: Overwrite file content", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing initial content")
			err = alice.StoreFile(aliceFile, []byte("initial"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Overwriting with new content")
			err = alice.StoreFile(aliceFile, []byte("overwritten"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading should show new content")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("overwritten")))
		})

		Specify("Test: Different users can have same filename", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Both store files with same name but different content")
			err = alice.StoreFile("shared.txt", []byte("alice's content"))
			Expect(err).To(BeNil())
			err = bob.StoreFile("shared.txt", []byte("bob's content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Each should see their own content")
			dataAlice, err := alice.LoadFile("shared.txt")
			Expect(err).To(BeNil())
			Expect(dataAlice).To(Equal([]byte("alice's content")))

			dataBob, err := bob.LoadFile("shared.txt")
			Expect(err).To(BeNil())
			Expect(dataBob).To(Equal([]byte("bob's content")))
		})

		Specify("Test: Multiple appends", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing initial content")
			err = alice.StoreFile(aliceFile, []byte("0"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending multiple times")
			for i := 1; i <= 10; i++ {
				err = alice.AppendToFile(aliceFile, []byte("X"))
				Expect(err).To(BeNil())
			}

			userlib.DebugMsg("Loading should show all appends")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("0XXXXXXXXXX")))
		})

		Specify("Test: Append empty content", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("initial"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending empty content")
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("initial")))
		})

	})

	// ================================================
	// SHARING TESTS
	// ================================================
	Describe("Sharing Tests", func() {

		Specify("Test: Share with non-existent user should fail", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to share with non-existent user")
			_, err = alice.CreateInvitation(aliceFile, "nonexistent")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Share non-existent file should fail", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to share non-existent file")
			_, err = alice.CreateInvitation("nonexistent.txt", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Accept invitation with existing filename should fail", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file")
			err = alice.StoreFile(aliceFile, []byte("alice's content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob stores file with same name he wants to use")
			err = bob.StoreFile(bobFile, []byte("bob's content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts with existing filename - should fail")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Accept invitation with wrong sender should fail", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob tries to accept claiming Charles sent it")
			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Accept non-existent invitation should fail", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob tries to accept fake invitation")
			fakeUUID := uuid.New()
			err = bob.AcceptInvitation("alice", fakeUUID, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Shared user can modify file", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("original"))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob overwrites the file")
			err = bob.StoreFile(bobFile, []byte("bob modified"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice should see Bob's changes")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("bob modified")))
		})

		Specify("Test: Chain sharing A->B->C", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares with Bob")
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob shares with Charles")
			invite2, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles can read the file")
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content")))

			userlib.DebugMsg("Charles can append")
			err = charles.AppendToFile(charlesFile, []byte(" appended"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Everyone sees the append")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content appended")))
		})

	})

	// ================================================
	// REVOCATION TESTS
	// ================================================
	Describe("Revocation Tests", func() {

		Specify("Test: Revoke from non-shared user should fail", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoking from user who doesn't have access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Revoke non-existent file should fail", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoking non-existent file")
			err = alice.RevokeAccess("nonexistent.txt", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Non-owner cannot revoke", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob (non-owner) tries to revoke Charles")
			err = bob.RevokeAccess(bobFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Owner can still access after revoking all users", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice can still access")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content")))

			userlib.DebugMsg("Alice can still append")
			err = alice.AppendToFile(aliceFile, []byte(" more"))
			Expect(err).To(BeNil())

			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content more")))
		})

		Specify("Test: Re-share after revoke", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice re-shares with Bob")
			invite2, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// Bob needs to use a different filename since bobFile might still exist in his namespace
			err = bob.AcceptInvitation("alice", invite2, "newBobFile.txt")
			Expect(err).To(BeNil())

			data, err := bob.LoadFile("newBobFile.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content")))
		})

	})

	// ================================================
	// INTEGRITY/TAMPERING TESTS
	// ================================================
	Describe("Integrity Tests", func() {

		Specify("Test: Tampering with user data should be detected", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with datastore")
			datastoreMap := userlib.DatastoreGetMap()
			for key := range datastoreMap {
				userlib.DatastoreSet(key, []byte("corrupted data"))
				break
			}

			userlib.DebugMsg("Getting user should fail")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Tampering with file data should be detected", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting datastore state")
			datastoreMap := userlib.DatastoreGetMap()

			userlib.DebugMsg("Tampering with all entries")
			for key := range datastoreMap {
				original := datastoreMap[key]
				// Flip some bits
				corrupted := make([]byte, len(original))
				copy(corrupted, original)
				if len(corrupted) > 0 {
					corrupted[0] = corrupted[0] ^ 0xFF
				}
				userlib.DatastoreSet(key, corrupted)
			}

			userlib.DebugMsg("Loading file should fail")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Deleting file data should be detected", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Deleting all datastore entries except user")
			datastoreMap := userlib.DatastoreGetMap()
			count := 0
			for key := range datastoreMap {
				if count > 0 { // Skip first entry (likely user)
					userlib.DatastoreDelete(key)
				}
				count++
			}

			userlib.DebugMsg("Loading file should fail")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

	})

	// ================================================
	// EFFICIENCY TESTS
	// ================================================
	Describe("Efficiency Tests", func() {

		Specify("Test: Append efficiency - should not scale with file size", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// Store initial large file
			largeContent := make([]byte, 10000)
			for i := range largeContent {
				largeContent[i] = 'A'
			}
			err = alice.StoreFile(aliceFile, largeContent)
			Expect(err).To(BeNil())

			// Measure bandwidth of first append
			smallAppend := []byte("small")
			bw1 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, smallAppend)
			})

			// Measure bandwidth of second append (same size)
			bw2 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, smallAppend)
			})

			userlib.DebugMsg("First append bandwidth: %d, Second append bandwidth: %d", bw1, bw2)

			// Both should be similar (not scaling with file size)
			// Allow some tolerance for overhead
			Expect(bw2).To(BeNumerically("<=", bw1*2+1000))
		})

	})

	// ================================================
	// MULTIPLE DEVICE TESTS
	// ================================================
	Describe("Multiple Device Tests", func() {

		Specify("Test: Changes sync across devices", func() {
			userlib.DebugMsg("Creating user alice on desktop")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice logs in on laptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Desktop stores file")
			err = aliceDesktop.StoreFile(aliceFile, []byte("from desktop"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Laptop should see the file")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("from desktop")))

			userlib.DebugMsg("Laptop appends")
			err = aliceLaptop.AppendToFile(aliceFile, []byte(" and laptop"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Desktop should see laptop's changes")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("from desktop and laptop")))
		})

		Specify("Test: Sharing from one device, accessing from another", func() {
			userlib.DebugMsg("Creating users")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Desktop stores file")
			err = aliceDesktop.StoreFile(aliceFile, []byte("content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Laptop creates invitation")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content")))
		})

	})

	// ================================================
	// EDGE CASE TESTS
	// ================================================
	Describe("Edge Case Tests", func() {

		Specify("Test: Special characters in filename", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			specialFilename := "file with spaces & special!@#$%chars.txt"
			err = alice.StoreFile(specialFilename, []byte("content"))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(specialFilename)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content")))
		})

		Specify("Test: Very long filename", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			longFilename := ""
			for i := 0; i < 1000; i++ {
				longFilename += "a"
			}

			err = alice.StoreFile(longFilename, []byte("content"))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(longFilename)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("content")))
		})

		Specify("Test: Large file content", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			largeContent := make([]byte, 100000)
			for i := range largeContent {
				largeContent[i] = byte(i % 256)
			}

			err = alice.StoreFile(aliceFile, largeContent)
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal(largeContent))
		})

		Specify("Test: Multiple files per user", func() {
			userlib.DebugMsg("Creating user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			for i := 0; i < 10; i++ {
				filename := "file" + string(rune('0'+i)) + ".txt"
				content := []byte("content" + string(rune('0'+i)))
				err = alice.StoreFile(filename, content)
				Expect(err).To(BeNil())
			}

			for i := 0; i < 10; i++ {
				filename := "file" + string(rune('0'+i)) + ".txt"
				expectedContent := []byte("content" + string(rune('0'+i)))
				data, err := alice.LoadFile(filename)
				Expect(err).To(BeNil())
				Expect(data).To(Equal(expectedContent))
			}
		})

		Specify("Test: Share to multiple users", func() {
			userlib.DebugMsg("Creating users")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("shared content"))
			Expect(err).To(BeNil())

			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).To(BeNil())

			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).To(BeNil())

			invite3, err := alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", invite3, dorisFile)
			Expect(err).To(BeNil())

			// All should see the same content
			data, _ := bob.LoadFile(bobFile)
			Expect(data).To(Equal([]byte("shared content")))
			data, _ = charles.LoadFile(charlesFile)
			Expect(data).To(Equal([]byte("shared content")))
			data, _ = doris.LoadFile(dorisFile)
			Expect(data).To(Equal([]byte("shared content")))

			// Revoke one, others should still have access
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("shared content")))

			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("shared content")))
		})

	})

})