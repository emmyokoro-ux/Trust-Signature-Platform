;; Secure Document Authentication & Multi-Party Signature Registry Smart Contract
;; Purpose: An enterprise-grade blockchain system for managing cryptographically-secured digital document 
;; signatures with comprehensive verification, multi-party authentication, lifecycle management, and 
;; immutable audit trails for legal contracts, business agreements, and official documentation

;; CORE DATA STRUCTURES AND PERSISTENT STORAGE

;; Primary registry mapping document content hashes to comprehensive metadata
(define-map registered-document-metadata-store
  { document-hash-identifier: (buff 32) }
  {
    original-document-creator: principal,
    document-display-title: (string-utf8 256),
    document-detailed-description: (string-utf8 1024),
    blockchain-creation-timestamp: uint,
    current-document-lifecycle-status: (string-utf8 20),
    verified-signature-count-total: uint
  }
)

;; Comprehensive signature authentication records with cryptographic proof storage
(define-map authenticated-signature-evidence-store
  { 
    target-document-hash: (buff 32),
    authenticating-party-principal: principal
  }
  {
    digital-signature-proof: (buff 65),
    signature-creation-timestamp: uint,
    signature-contextual-message: (string-utf8 256),
    signature-verification-status: bool
  }
)

;; Authorized user cryptographic public key registry for signature verification
(define-map registered-user-public-key-store
  { authorized-key-owner: principal }
  { compressed-secp256k1-public-key: (buff 33) }
)

;; Global system statistics tracking registered documents
(define-data-var system-wide-document-registry-count uint u0)

;; COMPREHENSIVE ERROR HANDLING AND STATUS DEFINITIONS

(define-constant ERR-UNAUTHORIZED-DOCUMENT-ACCESS (err u401))
(define-constant ERR-REQUESTED-DOCUMENT-NOT-FOUND (err u404))
(define-constant ERR-DOCUMENT-HASH-ALREADY-REGISTERED (err u409))
(define-constant ERR-CRYPTOGRAPHIC-SIGNATURE-VERIFICATION-FAILED (err u400))
(define-constant ERR-DUPLICATE-SIGNATURE-FROM-SAME-USER (err u409))
(define-constant ERR-DOCUMENT-ACCESS-REVOKED-STATUS (err u403))
(define-constant ERR-USER-PUBLIC-KEY-NOT-REGISTERED (err u404))
(define-constant ERR-MALFORMED-PUBLIC-KEY-FORMAT (err u400))
(define-constant ERR-INVALID-FUNCTION-PARAMETERS (err u400))

;; Document lifecycle status enumeration constants
(define-constant active-document-status u"active")
(define-constant revoked-document-status u"revoked")

;; Cryptographic key format validation constants
(define-constant secp256k1-compressed-prefix-even 0x02)
(define-constant secp256k1-compressed-prefix-odd 0x03)

;; DOCUMENT INFORMATION RETRIEVAL FUNCTIONS

;; Retrieve comprehensive document metadata by content hash identifier
(define-read-only (fetch-complete-document-information (document-hash-identifier (buff 32)))
  (map-get? registered-document-metadata-store { document-hash-identifier: document-hash-identifier })
)

;; Verify document registration status in the blockchain registry
(define-read-only (verify-document-registration-status (document-hash-identifier (buff 32)))
  (is-some (map-get? registered-document-metadata-store { document-hash-identifier: document-hash-identifier }))
)

;; Retrieve specific signature authentication details for document and signer combination
(define-read-only (fetch-signature-authentication-record (target-document-hash (buff 32)) (authenticating-party-principal principal))
  (map-get? authenticated-signature-evidence-store { target-document-hash: target-document-hash, authenticating-party-principal: authenticating-party-principal })
)

;; Verify if specified principal has authenticated the target document
(define-read-only (confirm-user-document-authentication (target-document-hash (buff 32)) (authenticating-party-principal principal))
  (is-some (map-get? authenticated-signature-evidence-store { target-document-hash: target-document-hash, authenticating-party-principal: authenticating-party-principal }))
)

;; Calculate total verified signatures for specified document
(define-read-only (calculate-document-signature-total (document-hash-identifier (buff 32)))
  (let ((retrieved-document-metadata (fetch-complete-document-information document-hash-identifier)))
    (if (is-some retrieved-document-metadata)
      (get verified-signature-count-total (unwrap-panic retrieved-document-metadata))
      u0
    )
  )
)

;; Retrieve registered cryptographic public key for specified user
(define-read-only (fetch-user-registered-public-key (authorized-key-owner principal))
  (map-get? registered-user-public-key-store { authorized-key-owner: authorized-key-owner })
)

;; Perform cryptographic signature verification against message hash and public key
(define-read-only (perform-cryptographic-signature-verification 
    (target-message-hash (buff 32))
    (provided-signature-proof (buff 65))
    (verification-public-key (buff 33)))
  (is-eq (secp256k1-recover? target-message-hash provided-signature-proof) (ok verification-public-key))
)

;; Retrieve system-wide registered document statistics
(define-read-only (fetch-total-system-document-count)
  (var-get system-wide-document-registry-count)
)

;; INPUT VALIDATION AND FORMAT VERIFICATION FUNCTIONS

;; Validate compressed secp256k1 public key format compliance
(define-read-only (validate-secp256k1-public-key-format (verification-public-key (buff 33)))
  (let (
    (key-first-byte-value (unwrap-panic (element-at? verification-public-key u0)))
  )
    (or 
      (is-eq key-first-byte-value secp256k1-compressed-prefix-even)
      (is-eq key-first-byte-value secp256k1-compressed-prefix-odd)
    )
  )
)

;; Validate string parameter is non-empty and contains meaningful content
(define-read-only (validate-non-empty-string-input (string-parameter-input (string-utf8 1024)))
  (not (is-eq string-parameter-input u""))
)

;; Validate document description format (UTF-8 compliance verification)
(define-read-only (validate-document-description-format (document-detailed-description (string-utf8 1024)))
  ;; Type system ensures UTF-8 validity, function provides explicit validation interface
  true
)

;; USER CRYPTOGRAPHIC KEY MANAGEMENT FUNCTIONS

;; Register user's secp256k1 public key for signature verification purposes
(define-public (register-cryptographic-public-key (compressed-secp256k1-public-key (buff 33)))
  (begin
    ;; Perform comprehensive public key format validation
    (asserts! (validate-secp256k1-public-key-format compressed-secp256k1-public-key) ERR-MALFORMED-PUBLIC-KEY-FORMAT)
    
    (map-set registered-user-public-key-store
      { authorized-key-owner: tx-sender }
      { compressed-secp256k1-public-key: compressed-secp256k1-public-key }
    )
    (ok true)
  )
)

;; DOCUMENT LIFECYCLE AND REGISTRY MANAGEMENT FUNCTIONS

;; Register new document with comprehensive metadata in blockchain registry
(define-public (create-new-document-registration 
    (document-hash-identifier (buff 32))
    (document-display-title (string-utf8 256))
    (document-detailed-description (string-utf8 1024)))
  (let ((current-blockchain-timestamp (unwrap-panic (get-block-info? time (- block-height u1)))))
    ;; Comprehensive input parameter validation
    (asserts! (validate-non-empty-string-input document-display-title) ERR-INVALID-FUNCTION-PARAMETERS)
    (asserts! (validate-document-description-format document-detailed-description) ERR-INVALID-FUNCTION-PARAMETERS)
    
    (if (verify-document-registration-status document-hash-identifier)
      ERR-DOCUMENT-HASH-ALREADY-REGISTERED
      (begin
        (map-set registered-document-metadata-store
          { document-hash-identifier: document-hash-identifier }
          {
            original-document-creator: tx-sender,
            document-display-title: document-display-title,
            document-detailed-description: document-detailed-description,
            blockchain-creation-timestamp: current-blockchain-timestamp,
            current-document-lifecycle-status: active-document-status,
            verified-signature-count-total: u0
          }
        )
        (var-set system-wide-document-registry-count (+ (var-get system-wide-document-registry-count) u1))
        (ok true)
      )
    )
  )
)

;; Update existing document metadata (restricted to original creator)
(define-public (modify-document-registry-information
    (document-hash-identifier (buff 32))
    (updated-document-title (string-utf8 256))
    (updated-document-description (string-utf8 1024)))
  (let ((retrieved-document-metadata (fetch-complete-document-information document-hash-identifier)))
    (asserts! (is-some retrieved-document-metadata) ERR-REQUESTED-DOCUMENT-NOT-FOUND)
    (asserts! (validate-non-empty-string-input updated-document-title) ERR-INVALID-FUNCTION-PARAMETERS)
    (asserts! (validate-document-description-format updated-document-description) ERR-INVALID-FUNCTION-PARAMETERS)
    
    (let ((current-document-metadata (unwrap-panic retrieved-document-metadata)))
      ;; Verify transaction sender is original document creator
      (asserts! (is-eq tx-sender (get original-document-creator current-document-metadata)) ERR-UNAUTHORIZED-DOCUMENT-ACCESS)
      
      ;; Update document metadata while preserving other registry fields
      (map-set registered-document-metadata-store
        { document-hash-identifier: document-hash-identifier }
        (merge current-document-metadata { 
          document-display-title: updated-document-title,
          document-detailed-description: updated-document-description
        })
      )
      (ok true)
    )
  )
)

;; Revoke document access and signature capabilities (creator authorization required)
(define-public (revoke-document-registry-access (document-hash-identifier (buff 32)))
  (let ((retrieved-document-metadata (fetch-complete-document-information document-hash-identifier)))
    (asserts! (is-some retrieved-document-metadata) ERR-REQUESTED-DOCUMENT-NOT-FOUND)
    
    (let ((current-document-metadata (unwrap-panic retrieved-document-metadata)))
      ;; Verify transaction sender is original document creator
      (asserts! (is-eq tx-sender (get original-document-creator current-document-metadata)) ERR-UNAUTHORIZED-DOCUMENT-ACCESS)
      
      ;; Update document lifecycle status to revoked state
      (map-set registered-document-metadata-store
        { document-hash-identifier: document-hash-identifier }
        (merge current-document-metadata { current-document-lifecycle-status: revoked-document-status })
      )
      (ok true)
    )
  )
)

;; CRYPTOGRAPHIC SIGNATURE CREATION AND VERIFICATION FUNCTIONS

;; Create authenticated digital signature with comprehensive verification process
(define-public (create-authenticated-document-signature 
    (target-document-hash (buff 32))
    (provided-cryptographic-signature (buff 65))
    (signature-contextual-message (string-utf8 256)))
  (let (
    (retrieved-document-metadata (fetch-complete-document-information target-document-hash))
    (current-blockchain-timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
    (user-registered-key-data (fetch-user-registered-public-key tx-sender))
  )
    (asserts! (is-some retrieved-document-metadata) ERR-REQUESTED-DOCUMENT-NOT-FOUND)
    (asserts! (is-some user-registered-key-data) ERR-USER-PUBLIC-KEY-NOT-REGISTERED)
    (asserts! (validate-non-empty-string-input signature-contextual-message) ERR-INVALID-FUNCTION-PARAMETERS)
    
    (let (
      (current-document-metadata (unwrap-panic retrieved-document-metadata))
      (user-verification-public-key (get compressed-secp256k1-public-key (unwrap-panic user-registered-key-data)))
      ;; Generate composite message hash from document hash and contextual message
      (composite-verification-hash (sha256 (concat target-document-hash (sha256 (unwrap! (to-consensus-buff? signature-contextual-message) ERR-CRYPTOGRAPHIC-SIGNATURE-VERIFICATION-FAILED)))))
    )
      ;; Verify document maintains active status for signature acceptance
      (asserts! (is-eq (get current-document-lifecycle-status current-document-metadata) active-document-status) ERR-DOCUMENT-ACCESS-REVOKED-STATUS)
      
      ;; Prevent duplicate signature attempts from identical user
      (asserts! (not (confirm-user-document-authentication target-document-hash tx-sender)) ERR-DUPLICATE-SIGNATURE-FROM-SAME-USER)
      
      ;; Perform comprehensive cryptographic signature authenticity verification
      (asserts! (perform-cryptographic-signature-verification composite-verification-hash provided-cryptographic-signature user-verification-public-key) ERR-CRYPTOGRAPHIC-SIGNATURE-VERIFICATION-FAILED)
      
      ;; Store verified signature authentication record in blockchain
      (map-set authenticated-signature-evidence-store
        { target-document-hash: target-document-hash, authenticating-party-principal: tx-sender }
        { 
          digital-signature-proof: provided-cryptographic-signature,
          signature-creation-timestamp: current-blockchain-timestamp,
          signature-contextual-message: signature-contextual-message,
          signature-verification-status: true
        }
      )
      
      ;; Increment document's verified signature counter
      (map-set registered-document-metadata-store
        { document-hash-identifier: target-document-hash }
        (merge current-document-metadata { verified-signature-count-total: (+ (get verified-signature-count-total current-document-metadata) u1) })
      )
      
      (ok true)
    )
  )
)

;; Invalidate specific user signature (document creator authorization required)
(define-public (invalidate-user-signature-authentication
    (target-document-hash (buff 32))
    (target-signature-owner principal))
  (let (
    (retrieved-document-metadata (fetch-complete-document-information target-document-hash))
    (retrieved-signature-data (fetch-signature-authentication-record target-document-hash target-signature-owner))
  )
    (asserts! (is-some retrieved-document-metadata) ERR-REQUESTED-DOCUMENT-NOT-FOUND)
    (asserts! (is-some retrieved-signature-data) ERR-CRYPTOGRAPHIC-SIGNATURE-VERIFICATION-FAILED)
    
    (let (
      (current-document-metadata (unwrap-panic retrieved-document-metadata))
      (current-signature-record (unwrap-panic retrieved-signature-data))
    )
      ;; Verify transaction sender is original document creator
      (asserts! (is-eq tx-sender (get original-document-creator current-document-metadata)) ERR-UNAUTHORIZED-DOCUMENT-ACCESS)
      
      ;; Decrement signature count only for previously valid signatures
      (if (get signature-verification-status current-signature-record)
        (map-set registered-document-metadata-store
          { document-hash-identifier: target-document-hash }
          (merge current-document-metadata { verified-signature-count-total: (- (get verified-signature-count-total current-document-metadata) u1) })
        )
        true
      )
      
      ;; Mark signature record as invalid in authentication store
      (map-set authenticated-signature-evidence-store
        { target-document-hash: target-document-hash, authenticating-party-principal: target-signature-owner }
        (merge current-signature-record { signature-verification-status: false })
      )
      (ok true)
    )
  )
)

;; BATCH VERIFICATION AND MULTI-PARTY AUTHENTICATION FUNCTIONS

;; Verify multiple party signatures for document (supports up to 10 signers)
(define-public (verify-multi-party-document-authentication
    (target-document-hash (buff 32))
    (signature-owner-principal-list (list 10 principal)))
  (let ((retrieved-document-metadata (fetch-complete-document-information target-document-hash)))
    (asserts! (is-some retrieved-document-metadata) ERR-REQUESTED-DOCUMENT-NOT-FOUND)
    
    (let ((current-document-metadata (unwrap-panic retrieved-document-metadata)))
      ;; Verify document maintains active status
      (asserts! (is-eq (get current-document-lifecycle-status current-document-metadata) active-document-status) ERR-DOCUMENT-ACCESS-REVOKED-STATUS)
      
      ;; Verify each principal in list has authenticated the document
      (ok (and
        ;; Handle empty list scenario gracefully
        (or (is-eq (len signature-owner-principal-list) u0) 
          (and
            ;; Verify each position in principal list up to maximum 10 signers
            (or (< (len signature-owner-principal-list) u1) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u0))))
            (or (< (len signature-owner-principal-list) u2) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u1))))
            (or (< (len signature-owner-principal-list) u3) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u2))))
            (or (< (len signature-owner-principal-list) u4) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u3))))
            (or (< (len signature-owner-principal-list) u5) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u4))))
            (or (< (len signature-owner-principal-list) u6) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u5))))
            (or (< (len signature-owner-principal-list) u7) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u6))))
            (or (< (len signature-owner-principal-list) u8) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u7))))
            (or (< (len signature-owner-principal-list) u9) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u8))))
            (or (< (len signature-owner-principal-list) u10) (confirm-user-document-authentication target-document-hash (unwrap-panic (element-at signature-owner-principal-list u9))))
          )
        )
      ))
    )
  )
)