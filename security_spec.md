# Kavach Security Console — Security Specification

## 1. Data Invariants
1. **Strict Ownership Isolation**: Every document under `/users/{userId}/deleted_apks/{apkRecordId}`, `/users/{userId}/hardening_state/{stepId}`, and `/users/{userId}/threat_analyses/{analysisId}` belongs strictly to `userId`. Only a verified authenticated user with `request.auth.uid == userId` and `request.auth.token.email_verified == true` may read or write their own subcollections.
2. **Identity Integrity**: `incoming().ownerId == request.auth.uid` on every create, and `incoming().ownerId == existing().ownerId` on every update.
3. **Immutable Suppression Tombstones**: Once a `DeletedApkRecord` is created, its `sha256`, `fileName`, `normalizedName`, `ownerId`, and `deletedAt` are immutable. Users may only delete a record via explicit registry purge if desired, never mutate a deleted record's hash or timestamp.
4. **Temporal Integrity**: `deletedAt`, `updatedAt`, and `analyzedAt` must strictly equal `request.time` on creation/update; client-forged timestamps are rejected.
5. **Path & Payload Bounds**: Every document ID matches `^[a-zA-Z0-9_\-]+$` (`<= 128` chars), and every string/integer field enforces explicit type, enum, regex, and `.size()` limits to prevent storage exhaustion or shadow field injection.

## 2. The "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Cross-User Read/Write**: Authenticated user `userB` attempts to read or create `/users/userA/deleted_apks/rec1`.
2. **Unverified Email Write**: Authenticated user `userA` with `email_verified: false` attempts to create `/users/userA/deleted_apks/rec1`.
3. **OwnerId Spoofing**: User `userA` writes to `/users/userA/deleted_apks/rec1` with `ownerId: "userB"`.
4. **Shadow Ghost Field**: User `userA` writes `DeletedApkRecord` containing an extra field `isAdmin: true`.
5. **Missing Required Field**: User `userA` creates `DeletedApkRecord` omitting `sha256`.
6. **Invalid SHA-256 Format**: User `userA` writes `sha256: "not-a-valid-sha256"` (must match `^[a-f0-9]{64}$`).
7. **Forged Timestamp**: User `userA` writes `deletedAt: new Date("2020-01-01T00:00:00Z")` instead of `serverTimestamp()`.
8. **ID Poisoning**: User `userA` targets document ID `"a".repeat(200)` (`> 128` chars) or containing `$`/`.`/`/`.
9. **String Overflow (Denial of Wallet)**: User `userA` creates `ThreatAnalysisRecord` with `summary` of 5,000 characters (`> 1500`).
10. **Invalid Enum Value**: User `userA` creates `DeletedApkRecord` with `riskLevel: "extreme"` or `deletionMethod: "hacked"`.
11. **Immutable Field Mutation**: User `userA` updates `/users/userA/hardening_state/step1` attempting to change `ownerId` or `stepKey`.
12. **Blanket List Scraping**: Unauthenticated user or `userB` attempts `list` on `/users/userA/deleted_apks`.
