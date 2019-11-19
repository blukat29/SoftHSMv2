#include "config.h"
#include "fatal.h"
#include "P11Interface.h"
#include "SoftHSM.h"

// Constructor
P11Interface::P11Interface()
{
    core.reset(new SoftHSMCore());
}

// Destructor
P11Interface::~P11Interface()
{
    core.reset();
}

// PKCS #11 initialisation function
CK_RV P11Interface::C_Initialize(CK_VOID_PTR pInitArgs)
{
	try
	{
		return core.get()->C_Initialize(pInitArgs);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// PKCS #11 finalisation function
CK_RV P11Interface::C_Finalize(CK_VOID_PTR pReserved)
{
	try
	{
		return core.get()->C_Finalize(pReserved);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about the PKCS #11 module
CK_RV P11Interface::C_GetInfo(CK_INFO_PTR pInfo)
{
	try
	{
		return core.get()->C_GetInfo(pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return a list of available slots
CK_RV P11Interface::C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	try
	{
		return core.get()->C_GetSlotList(tokenPresent, pSlotList, pulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about a slot
CK_RV P11Interface::C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	try
	{
		return core.get()->C_GetSlotInfo(slotID, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about a token in a slot
CK_RV P11Interface::C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	try
	{
		return core.get()->C_GetTokenInfo(slotID, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return the list of supported mechanisms for a given slot
CK_RV P11Interface::C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	try
	{
		return core.get()->C_GetMechanismList(slotID, pMechanismList, pulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return more information about a mechanism for a given slot
CK_RV P11Interface::C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	try
	{
		return core.get()->C_GetMechanismInfo(slotID, type, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise the token in the specified slot
CK_RV P11Interface::C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	try
	{
		return core.get()->C_InitToken(slotID, pPin, ulPinLen, pLabel);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise the user PIN
CK_RV P11Interface::C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	try
	{
		return core.get()->C_InitPIN(hSession, pPin, ulPinLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Change the PIN
CK_RV P11Interface::C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	try
	{
		return core.get()->C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Open a new session to the specified slot
CK_RV P11Interface::C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	try
	{
		return core.get()->C_OpenSession(slotID, flags, pApplication, notify, phSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Close the given session
CK_RV P11Interface::C_CloseSession(CK_SESSION_HANDLE hSession)
{
	try
	{
		return core.get()->C_CloseSession(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Close all open sessions
CK_RV P11Interface::C_CloseAllSessions(CK_SLOT_ID slotID)
{
	try
	{
		return core.get()->C_CloseAllSessions(slotID);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Retrieve information about the specified session
CK_RV P11Interface::C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	try
	{
		return core.get()->C_GetSessionInfo(hSession, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Determine the state of a running operation in a session
CK_RV P11Interface::C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	try
	{
		return core.get()->C_GetOperationState(hSession, pOperationState, pulOperationStateLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Set the operation sate in a session
CK_RV P11Interface::C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	try
	{
		return core.get()->C_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Login on the token in the specified session
CK_RV P11Interface::C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	try
	{
		return core.get()->C_Login(hSession, userType, pPin, ulPinLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Log out of the token in the specified session
CK_RV P11Interface::C_Logout(CK_SESSION_HANDLE hSession)
{
	try
	{
		return core.get()->C_Logout(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Create a new object on the token in the specified session using the given attribute template
CK_RV P11Interface::C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	try
	{
		return core.get()->C_CreateObject(hSession, pTemplate, ulCount, phObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Create a copy of the object with the specified handle
CK_RV P11Interface::C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	try
	{
		return core.get()->C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Destroy the specified object
CK_RV P11Interface::C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return core.get()->C_DestroyObject(hSession, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Determine the size of the specified object
CK_RV P11Interface::C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	try
	{
		return core.get()->C_GetObjectSize(hSession, hObject, pulSize);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Retrieve the specified attributes for the given object
CK_RV P11Interface::C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
		return core.get()->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Change or set the value of the specified attributes on the specified object
CK_RV P11Interface::C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
		return core.get()->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise object search in the specified session using the specified attribute template as search parameters
CK_RV P11Interface::C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
		return core.get()->C_FindObjectsInit(hSession, pTemplate, ulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Continue the search for objects in the specified session
CK_RV P11Interface::C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	try
	{
		return core.get()->C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finish searching for objects
CK_RV P11Interface::C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	try
	{
		return core.get()->C_FindObjectsFinal(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise encryption using the specified object and mechanism
CK_RV P11Interface::C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return core.get()->C_EncryptInit(hSession, pMechanism, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single operation encryption operation in the specified session
CK_RV P11Interface::C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
		return core.get()->C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Feed data to the running encryption operation in a session
CK_RV P11Interface::C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
		return core.get()->C_EncryptUpdate(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the encryption operation
CK_RV P11Interface::C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
		return core.get()->C_EncryptFinal(hSession, pEncryptedData, pulEncryptedDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise decryption using the specified object
CK_RV P11Interface::C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return core.get()->C_DecryptInit(hSession, pMechanism, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single operation decryption in the given session
CK_RV P11Interface::C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	try
	{
		return core.get()->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Feed data to the running decryption operation in a session
CK_RV P11Interface::C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	try
	{
		return core.get()->C_DecryptUpdate(hSession, pEncryptedData, ulEncryptedDataLen, pData, pDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the decryption operation
CK_RV P11Interface::C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	try
	{
		return core.get()->C_DecryptFinal(hSession, pData, pDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise digesting using the specified mechanism in the specified session
CK_RV P11Interface::C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	try
	{
		return core.get()->C_DigestInit(hSession, pMechanism);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Digest the specified data in a one-pass operation and return the resulting digest
CK_RV P11Interface::C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	try
	{
		return core.get()->C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running digest operation
CK_RV P11Interface::C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
		return core.get()->C_DigestUpdate(hSession, pPart, ulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running digest operation by digesting a secret key with the specified handle
CK_RV P11Interface::C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return core.get()->C_DigestKey(hSession, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the digest operation in the specified session and return the digest
CK_RV P11Interface::C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	try
	{
		return core.get()->C_DigestFinal(hSession, pDigest, pulDigestLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a signing operation using the specified key and mechanism
CK_RV P11Interface::C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return core.get()->C_SignInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Sign the data in a single pass operation
CK_RV P11Interface::C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
		return core.get()->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running signing operation with additional data
CK_RV P11Interface::C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
		return core.get()->C_SignUpdate(hSession, pPart, ulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise a running signing operation and return the signature
CK_RV P11Interface::C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
		return core.get()->C_SignFinal(hSession, pSignature, pulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a signing operation that allows recovery of the signed data
CK_RV P11Interface::C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return core.get()->C_SignRecoverInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single part signing operation that allows recovery of the signed data
CK_RV P11Interface::C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
		return core.get()->C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a verification operation using the specified key and mechanism
CK_RV P11Interface::C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return core.get()->C_VerifyInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single pass verification operation
CK_RV P11Interface::C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	try
	{
		return core.get()->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running verification operation with additional data
CK_RV P11Interface::C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
		return core.get()->C_VerifyUpdate(hSession, pPart, ulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the verification operation and check the signature
CK_RV P11Interface::C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	try
	{
		return core.get()->C_VerifyFinal(hSession, pSignature, ulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a verification operation the allows recovery of the signed data from the signature
CK_RV P11Interface::C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return core.get()->C_VerifyRecoverInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single part verification operation and recover the signed data
CK_RV P11Interface::C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	try
	{
		return core.get()->C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part encryption and digesting operation
CK_RV P11Interface::C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	try
	{
		return core.get()->C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part decryption and digesting operation
CK_RV P11Interface::C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
{
	try
	{
		return core.get()->C_DecryptDigestUpdate(hSession, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part signing and encryption operation
CK_RV P11Interface::C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	try
	{
		return core.get()->C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part decryption and verification operation
CK_RV P11Interface::C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	try
	{
		return core.get()->C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Generate a secret key using the specified mechanism
CK_RV P11Interface::C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	try
	{
		return core.get()->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Generate a key-pair using the specified mechanism
CK_RV P11Interface::C_GenerateKeyPair
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
	CK_ULONG ulPublicKeyAttributeCount, 
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey, 
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	try
	{
		return core.get()->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Wrap the specified key using the specified wrapping key and mechanism
CK_RV P11Interface::C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hWrappingKey, 
	CK_OBJECT_HANDLE hKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	try
	{
		return core.get()->C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Unwrap the specified key using the specified unwrapping key
CK_RV P11Interface::C_UnwrapKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hUnwrappingKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
)
{
	try
	{
		return core.get()->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulCount, phKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Derive a key from the specified base key
CK_RV P11Interface::C_DeriveKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hBaseKey, 
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
)
{
	try
	{
		return core.get()->C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Seed the random number generator with new data
CK_RV P11Interface::C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	try
	{
		return core.get()->C_SeedRandom(hSession, pSeed, ulSeedLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Generate the specified amount of random data
CK_RV P11Interface::C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
	try
	{
		return core.get()->C_GenerateRandom(hSession, pRandomData, ulRandomLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Legacy function
CK_RV P11Interface::C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	try
	{
		return core.get()->C_GetFunctionStatus(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Legacy function
CK_RV P11Interface::C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	try
	{
		return core.get()->C_CancelFunction(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Wait or poll for a slot even on the specified slot
CK_RV P11Interface::C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	try
	{
		return core.get()->C_WaitForSlotEvent(flags, pSlot, pReserved);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}
