/**
 * SSI Healthcare Mobile - Plain Language Utilities
 *
 * Transforms technical SSI terminology into user-friendly language.
 * Used by CredentialShareSheet, QRResultSheet, and other consent UIs.
 */

// -- Verifier Name Mappings --

const KNOWN_VERIFIERS: Record<string, string> = {
  'did:key:z6Mk': 'Healthcare Provider',
  'did:web:hospital': 'Hospital System',
  'did:web:pharmacy': 'Pharmacy',
  'did:web:insurance': 'Insurance Company',
  'did:web:gov': 'Government Agency',
  'did:web:employer': 'Employer',
};

/**
 * Get a friendly name for a verifier DID
 */
export function getVerifierDisplayName(verifierDid: string, fallbackName?: string): string {
  // Check for known verifier patterns
  for (const [pattern, name] of Object.entries(KNOWN_VERIFIERS)) {
    if (verifierDid.startsWith(pattern)) {
      return name;
    }
  }
  
  // Use the provided fallback name if available
  if (fallbackName) {
    return fallbackName;
  }
  
  // Extract domain from did:web
  if (verifierDid.startsWith('did:web:')) {
    const domain = verifierDid.replace('did:web:', '').replace(/%3A/g, ':');
    return domain.charAt(0).toUpperCase() + domain.slice(1);
  }
  
  return 'Unknown Organization';
}

// -- Credential Type Mappings --

const CREDENTIAL_TYPE_NAMES: Record<string, string> = {
  VerifiableCredential: 'Document',
  MedicalLicenseCredential: 'Medical License',
  NursingLicenseCredential: 'Nursing License',
  InsuranceCredential: 'Insurance Card',
  VaccinationCredential: 'Vaccination Record',
  ImmunizationCredential: 'Immunization Record',
  PrescriptionCredential: 'Prescription',
  LabResultCredential: 'Lab Results',
  PatientIdentityCredential: 'Patient ID',
  EmergencyContactCredential: 'Emergency Contact',
  HealthCertificateCredential: 'Health Certificate',
  ProofOfAgeCredential: 'Proof of Age',
  // THE TYPES THIS SYSTEM ACTUALLY ISSUES. They were missing, so the wallet's
  // own list rendered "HealthCardCredential" — the wire name — to the holder
  // whose identity it is (measured 19 Sep 2026).
  HealthCardCredential: 'Health Card',
  HealthRecordCredential: 'Health Record',
  ProfessionalLicenceCredential: 'Professional Licence',
};

/**
 * Get a plain language name for a credential type
 */
export function getCredentialTypeName(type: string): string {
  return CREDENTIAL_TYPE_NAMES[type] || formatCamelCase(type);
}

// -- Purpose Transformations --

const PURPOSE_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  { pattern: /verify.*licens/i, replacement: 'confirm you have a valid license' },
  { pattern: /verify.*identity/i, replacement: 'confirm your identity' },
  { pattern: /verify.*age/i, replacement: 'confirm your age' },
  { pattern: /verify.*vaccination/i, replacement: 'confirm your vaccination status' },
  { pattern: /verify.*insurance/i, replacement: 'confirm your insurance coverage' },
  { pattern: /verify.*employment/i, replacement: 'confirm your employment' },
  { pattern: /request.*credential/i, replacement: 'see your credentials' },
  { pattern: /presentation.*request/i, replacement: 'verify your information' },
];

/**
 * Transform a technical purpose into plain English
 */
export function transformPurpose(purpose: string): string {
  if (!purpose) return 'verify your information';
  
  for (const { pattern, replacement } of PURPOSE_PATTERNS) {
    if (pattern.test(purpose)) {
      return replacement;
    }
  }
  
  // If no pattern matches, try to make it more readable
  return purpose
    .replace(/^to\s+/i, '')
    .replace(/verifiable\s+/gi, '')
    .replace(/presentation\s+/gi, '')
    .toLowerCase();
}

// -- Field Name Mappings --

const FIELD_NAMES: Record<string, string> = {
  givenName: 'First Name',
  familyName: 'Last Name',
  dateOfBirth: 'Date of Birth',
  dob: 'Birthday',
  ssn: 'Social Security Number',
  socialSecurityNumber: 'Social Security Number',
  licenseNumber: 'License Number',
  licenseType: 'License Type',
  expirationDate: 'Valid Until',
  issuanceDate: 'Issued On',
  bloodType: 'Blood Type',
  allergies: 'Known Allergies',
  insuranceId: 'Insurance ID',
  policyNumber: 'Policy Number',
  memberId: 'Member ID',
  groupNumber: 'Group Number',
  immunizationType: 'Vaccine Type',
  vaccineName: 'Vaccine Name',
  vaccineManufacturer: 'Manufacturer',
  lotNumber: 'Lot Number',
  administrationDate: 'Date Given',
  nextDoseDate: 'Next Dose Due',
  prescriberName: 'Prescribed By',
  prescriberLicense: 'Prescriber License',
  dosage: 'Dosage',
  frequency: 'How Often',
  refills: 'Refills Left',
  credentialSubject: 'About',
  type: 'Document Type',
};

/**
 * Get a plain language name for a field key
 */
/**
 * A claim path as a person reads it.
 *
 * WHY THIS EXISTS AS ONE FUNCTION. There were THREE humanisers for the same job:
 * `FIELD_NAMES` + `formatCamelCase` in this file, `DATA_TYPE_DISPLAY` in
 * ConsentScreen, and a naive split in THAT map's fallback. They drifted, and the
 * drift is what a holder was shown: "Medication.start Date", "Patient Id",
 * "Medication.dosage" — a camelCase split that never split the DOT, never handled
 * an acronym, and left every word after the first lowercase. Measured on the
 * patient's own device, 24 Sep 2026.
 *
 * Three shapes a claim arrives in, all handled:
 *   "patientId"                 -> "Patient ID"
 *   "Medication.dosage"         -> "Dosage"
 *   "credentialSubject.name"    -> "Name"
 *
 * The full-path map comes first because a leaf alone is often ambiguous — "Name"
 * could be a person or a medicine, and only the container says which.
 */
const CLAIM_PATH_LABELS: Record<string, string> = {
  'medication.name': 'Medicine',
  'medication.dosage': 'Dosage',
  'medication.frequency': 'How Often',
  'medication.route': 'How Taken',
  'medication.startdate': 'Start Date',
  'medication.enddate': 'End Date',
  'patientid': 'Patient ID',
  'patient.name': 'Patient Name',
  'patientname': 'Patient Name',
  'prescribedby.name': 'Prescribed By',
  'issuedat': 'Issued At',
};

/** Leaf labels, for when the container adds nothing. */
const CLAIM_LEAF_LABELS: Record<string, string> = {
  id: 'ID',
  did: 'Identifier',
  name: 'Name',
  dosage: 'Dosage',
  frequency: 'How Often',
  route: 'How Taken',
  startdate: 'Start Date',
  enddate: 'End Date',
  issuedat: 'Issued At',
  prescribedby: 'Prescribed By',
};

/** Words that are acronyms and must not be title-cased into "Id". */
const ACRONYMS = new Set(['id', 'did', 'dob', 'ssn', 'mrn', 'nid', 'url', 'uri', 'jwt', 'otp', 'pin', 'ip']);

/** "patientName" -> "Patient Name"; "start_date" -> "Start Date"; "mrn" -> "MRN". */
function titleCaseWords(segment: string): string {
  return segment
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => {
      const lower = word.toLowerCase();
      if (ACRONYMS.has(lower)) return word.toUpperCase();
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    })
    .join(' ');
}

export function formatClaimLabel(path: string): string {
  const cleaned = String(path ?? '').trim();
  if (cleaned.length === 0) return '';

  // Normalise only for LOOKUP: drop a leading credentialSubject, lowercase, and
  // collapse camelCase so "startDate" and "startdate" hit the same key.
  const lookup = cleaned
    .replace(/^credentialSubject\./, '')
    .split('.')
    .map((seg) => seg.toLowerCase())
    .join('.');

  const full = CLAIM_PATH_LABELS[lookup];
  if (full) return full;

  // THE ORIGINAL CASE, NOT THE LOOKUP FORM. `lookup` is lowercased so map keys
  // match, and lowercasing also destroys the camelCase boundaries the fallback
  // needs — "someUnknownField" became "someunknownfield" and rendered as
  // "Someunknownfield". The fallback must split the string as the ISSUER wrote it.
  const originalSegments = cleaned.replace(/^credentialSubject\./, '').split('.').filter(Boolean);
  const leaf = originalSegments[originalSegments.length - 1] ?? cleaned;
  const leafLabel = CLAIM_LEAF_LABELS[leaf.toLowerCase()];
  if (leafLabel) return leafLabel;

  // Last resort: humanise whatever it is. Never return the raw path — a dotted
  // path reaching a holder is the defect this function exists to prevent.
  return titleCaseWords(leaf);
}

export function getFieldDisplayName(fieldKey: string): string {
  // The map first, then THE ONE humaniser — not formatCamelCase, which turned
  // "patientId" into "Patient Id" and is the same defect formatClaimLabel was
  // written to remove. Two fallbacks is how the credential detail and the consent
  // screen came to disagree in the first place.
  return FIELD_NAMES[fieldKey] || formatClaimLabel(fieldKey);
}

// -- Sensitive Field Detection --

const SENSITIVE_FIELDS = new Set([
  'ssn',
  'socialsecuritynumber',
  'dateofbirth',
  'dob',
  'address',
  'phone',
  'phonenumber',
  'email',
  'bloodtype',
  'allergies',
  'medicalrecordnumber',
  'mrn',
]);

/**
 * Check if a field contains sensitive information
 */
export function isSensitiveField(fieldKey: string): boolean {
  return SENSITIVE_FIELDS.has(fieldKey.toLowerCase().replace(/[_-]/g, ''));
}

// -- Helper Functions --

/**
 * Convert camelCase or PascalCase to Title Case with spaces
 */
function formatCamelCase(str: string): string {
  return str
    .replace(/([A-Z])/g, ' $1')
    .replace(/_/g, ' ')
    .replace(/^\w/, (c) => c.toUpperCase())
    .trim();
}

// -- Presentation Request Formatting --

interface PresentationRequestInfo {
  verifierName: string;
  verifierDid: string;
  /** The name is the verifier's own claim, not something this wallet checked. */
  verifierNameIsSelfAsserted: boolean;
  purpose: string;
  requestedTypes: string[];
  /** This wallet RECOGNISES the verifier. Never merely "the DID parsed". */
  isVerified: boolean;
}

/**
 * Extract plain language info from a presentation request
 * Handles both SDK PresentationRequest format and raw OID4VP format
 */
export function formatPresentationRequest(request: {
  // SDK PresentationRequest format
  verifier?: string | { id?: string; name?: string };
  id?: string;
  purpose?: string;
  requestedCredentials?: Array<{ type?: string; fields?: string[] }>;
  // OID4VP raw format
  client_id?: string;
  /** The verifier's own claim about its name. Asserted, not verified. */
  client_metadata?: { client_name?: string };
  presentation_definition?: {
    purpose?: string;
    input_descriptors?: Array<{ name?: string; purpose?: string }>;
  };
}): PresentationRequestInfo {
  // Get verifier DID - handle both string and object formats
  let verifierDid: string;
  let verifierDisplayName: string | undefined;
  
  if (typeof request.verifier === 'string') {
    verifierDid = request.verifier;
    verifierDisplayName = undefined;
  } else if (request.verifier) {
    verifierDid = request.verifier.id || '';
    verifierDisplayName = request.verifier.name;
  } else {
    verifierDid = request.client_id || '';
    verifierDisplayName = request.client_metadata?.client_name;
  }
  if (!verifierDisplayName) verifierDisplayName = request.client_metadata?.client_name;

  const verifierName = getVerifierDisplayName(verifierDid, verifierDisplayName);
  // RECOGNISED means "this wallet knows who this is", which is a different and
  // much stronger statement than "they told us a name". Only a pinned entry in
  // KNOWN_VERIFIERS counts; a self-asserted `client_name` does not.
  const isRecognised = Object.keys(KNOWN_VERIFIERS).some((p) => verifierDid.startsWith(p));
  
  // Get purpose from various locations
  const purpose = transformPurpose(
    request.purpose ||
    request.presentation_definition?.purpose ||
    request.presentation_definition?.input_descriptors?.[0]?.purpose ||
    ''
  );
  
  // Get requested credential types from SDK format or OID4VP format
  let requestedTypes: string[];
  if (request.requestedCredentials && request.requestedCredentials.length > 0) {
    requestedTypes = request.requestedCredentials
      .map(cred => getCredentialTypeName(cred.type || 'Credential'));
  } else {
    requestedTypes = (request.presentation_definition?.input_descriptors || [])
      .map(desc => getCredentialTypeName(desc.name || 'Credential'));
  }
  
  // NOT `verifierDid.startsWith('did:')`, which is what this used to be.
  //
  // That made EVERY syntactically valid DID a "Verified organisation" — the
  // wallet displayed a verified badge beside the words "Unknown Organization",
  // asserting it had checked something about a party it could not even name.
  // In a system whose whole claim is verifiable assertions, a badge that means
  // "this string begins with did:" is worse than no badge: it is a false
  // assurance the holder has no way to see through.
  //
  // Recognition is the honest bar this wallet can actually meet today. Proving
  // the verifier controls the DID needs a signed request object, which this
  // deployment does not yet issue.
  const isVerified = isRecognised;

  return {
    verifierName,
    verifierDid,
    /** True only when the name came from the verifier rather than a fallback. */
    verifierNameIsSelfAsserted: !isRecognised && Boolean(verifierDisplayName),
    purpose,
    requestedTypes,
    isVerified,
  };
}

/**
 * Generate a user-friendly summary sentence for a presentation request
 */
export function getPresentationSummary(info: PresentationRequestInfo): string {
  const types = info.requestedTypes.join(', ');
  
  if (info.requestedTypes.length === 0) {
    return `${info.verifierName} wants to ${info.purpose}.`;
  }
  
  if (info.requestedTypes.length === 1) {
    return `${info.verifierName} wants to see your ${types}.`;
  }
  
  return `${info.verifierName} wants to see: ${types}.`;
}
