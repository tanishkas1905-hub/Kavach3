/**
 * Verification suite specification for the "Dirty Dozen" adversarial payloads
 * against firestore.rules (used with @firebase/rules-unit-testing when emulator is running).
 */
export const DIRTY_DOZEN_PAYLOADS = [
  {
    name: '1. Cross-user read/write',
    actorUid: 'userB',
    path: 'users/userA/deleted_apks/rec_1',
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '2. Unverified email write',
    actorUid: 'userA',
    emailVerified: false,
    path: 'users/userA/deleted_apks/rec_1',
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '3. OwnerId spoofing',
    actorUid: 'userA',
    payload: { ownerId: 'userB' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '4. Shadow ghost field injection',
    actorUid: 'userA',
    payload: { isAdmin: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '5. Missing required sha256 field',
    actorUid: 'userA',
    payload: { fileName: 'update.apk' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '6. Invalid sha256 regex',
    actorUid: 'userA',
    payload: { sha256: 'invalid-hash' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '7. Forged client timestamp',
    actorUid: 'userA',
    payload: { deletedAt: '2020-01-01T00:00:00Z' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '8. Document ID poisoning (>128 chars)',
    actorUid: 'userA',
    docId: 'a'.repeat(200),
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '9. Summary string overflow (>1500 chars)',
    actorUid: 'userA',
    payload: { summary: 'x'.repeat(2000) },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '10. Invalid enum value for riskLevel',
    actorUid: 'userA',
    payload: { riskLevel: 'extreme' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '11. Immutable field mutation on hardening_state',
    actorUid: 'userA',
    payload: { stepKey: 'tampered_key' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '12. Unauthenticated blanket list scraping',
    actorUid: null,
    path: 'users/userA/deleted_apks',
    expected: 'PERMISSION_DENIED',
  },
];
