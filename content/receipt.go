package content

import ahp "github.com/agenthooksprotocol/go-sdk"

// ReferenceFromReceipt explicitly drops upload confirmation metadata. A receipt
// confirms uploaded bytes; only its opaque ref belongs in an event or effect.
// The caller must validate the receipt against the bytes it uploaded first.
func ReferenceFromReceipt(receipt ahp.ContentUploadReceipt) ahp.ContentReference {
	return ahp.ContentReference{Ref: receipt.Ref}
}
