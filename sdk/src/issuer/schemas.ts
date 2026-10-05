/**
 * Healthcare Verifiable Credential Schemas
 *
 * Maps hospital data models to W3C VC credential subjects.
 * Based on available hospital Prisma models:
 *   - Patient (demographics, allergies, medicalHistory)
 *   - VitalSign (type, value, unit, status, notes, recordedAt)
 *   - Medication (name, dosage, frequency, route, startDate, endDate, status)
 *   - Appointment (date, type, department, status, reason, diagnosis, doctor)
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Shared sub-schemas
// ---------------------------------------------------------------------------

const IsoDateString = z.string().datetime({ offset: true }).or(z.string().regex(/^\d{4}-\d{2}-\d{2}$/));

const DoctorSchema = z.object({
  name: z.string(),
  specialty: z.string().optional(),
  licenseNumber: z.string().optional(),
});

const AddressSchema = z.object({
  street: z.string().optional(),
  city: z.string().optional(),
  state: z.string().optional(),
  zip: z.string().optional(),
}).optional();

// ---------------------------------------------------------------------------
// PatientProfileCredential
// Subject: patient demographics, allergies, medical history
// ---------------------------------------------------------------------------

export const PatientProfileSubjectSchema = z.object({
  id: z.string().optional(),           // Patient DID (set when patient has wallet)
  patientId: z.string(),               // Hospital internal ID
  name: z.string(),
  dateOfBirth: z.string(),
  age: z.number().optional(),
  gender: z.string().optional(),
  phone: z.string().optional(),
  email: z.string().email().optional(),
  address: AddressSchema,
  bloodType: z.string().optional(),
  allergies: z.array(z.string()).default([]),
  medicalHistory: z.array(z.string()).default([]),
  insurance: z.object({
    provider: z.string(),
    plan: z.string().optional(),
    memberId: z.string().optional(),
  }).optional(),
});

export type PatientProfileSubject = z.infer<typeof PatientProfileSubjectSchema>;

// ---------------------------------------------------------------------------
// VitalSignsCredential
// Subject: one or more vital sign readings
// ---------------------------------------------------------------------------

export const VitalReadingSchema = z.object({
  type: z.string(),              // e.g. "BLOOD_PRESSURE", "HEART_RATE"
  value: z.string(),
  unit: z.string().optional(),
  status: z.string().optional(), // e.g. "NORMAL", "HIGH", "LOW"
  notes: z.string().optional(),
  recordedAt: IsoDateString,
});

export const VitalSignsSubjectSchema = z.object({
  id: z.string().optional(),
  patientId: z.string(),
  patientName: z.string(),
  readings: z.array(VitalReadingSchema).min(1),
  recordedBy: DoctorSchema.optional(),
  facility: z.string().optional(),
});

export type VitalSignsSubject = z.infer<typeof VitalSignsSubjectSchema>;

// ---------------------------------------------------------------------------
// PrescriptionCredential
// Subject: a prescribed medication / treatment
// ---------------------------------------------------------------------------

export const PrescriptionSubjectSchema = z.object({
  id: z.string().optional(),
  patientId: z.string(),
  patientName: z.string(),
  medication: z.object({
    name: z.string(),
    dosage: z.string(),
    frequency: z.string(),
    route: z.string().optional(),       // oral, IV, etc.
    startDate: z.string(),
    endDate: z.string().optional(),
    reason: z.string().optional(),
    instructions: z.string().optional(),
    status: z.string().optional(),
  }),
  prescribedBy: DoctorSchema,
  issuedAt: IsoDateString,
});

export type PrescriptionSubject = z.infer<typeof PrescriptionSubjectSchema>;

// ---------------------------------------------------------------------------
// AppointmentDiagnosisCredential
// Subject: appointment record including diagnosis
// ---------------------------------------------------------------------------

export const AppointmentDiagnosisSubjectSchema = z.object({
  id: z.string().optional(),
  patientId: z.string(),
  patientName: z.string(),
  appointment: z.object({
    date: z.string(),
    time: z.string().optional(),
    type: z.string().optional(),
    department: z.string().optional(),
    status: z.string().optional(),
    reason: z.string().optional(),
    urgency: z.string().optional(),
  }),
  diagnosis: z.string().optional(),
  prescription: z.string().optional(),    // Free-text prescription from appointment
  notes: z.string().optional(),
  doctor: DoctorSchema.optional(),
  facility: z.string().optional(),
});

export type AppointmentDiagnosisSubject = z.infer<typeof AppointmentDiagnosisSubjectSchema>;

// ---------------------------------------------------------------------------
// ImmunizationCredential
// ---------------------------------------------------------------------------

export const ImmunizationSubjectSchema = z.object({
  id: z.string().optional(),
  patientId: z.string(),
  patientName: z.string(),
  vaccine: z.object({
    name: z.string(),
    lotNumber: z.string().optional(),
    manufacturer: z.string().optional(),
    dose: z.string().optional(),
    site: z.string().optional(),
    route: z.string().optional(),
  }),
  administeredAt: IsoDateString,
  administeredBy: DoctorSchema.optional(),
  nextDoseDate: z.string().optional(),
  facility: z.string().optional(),
});

export type ImmunizationSubject = z.infer<typeof ImmunizationSubjectSchema>;

// ---------------------------------------------------------------------------
// DischargeSummaryCredential
// ---------------------------------------------------------------------------

export const DischargeSummarySubjectSchema = z.object({
  id: z.string().optional(),
  patientId: z.string(),
  patientName: z.string(),
  admissionDate: IsoDateString,
  dischargeDate: IsoDateString,
  diagnosis: z.string(),
  procedures: z.array(z.string()).default([]),
  medications: z.array(z.string()).default([]),
  followUpInstructions: z.string().optional(),
  condition: z.string().optional(),
  attendingPhysician: DoctorSchema.optional(),
  facility: z.string().optional(),
});

export type DischargeSummarySubject = z.infer<typeof DischargeSummarySubjectSchema>;

// ---------------------------------------------------------------------------
// Type lookup map
// ---------------------------------------------------------------------------

/**
 * JSON-LD contexts per credential type.
 *
 * VC Data Model 2.0 — the first entry must be the v2 credentials context, which
 * is what identifies the data model to a verifier. These named
 * `https://www.w3.org/2018/credentials/v1` before the migration; issuing v1 from
 * the SDK while the backend issues v2 would mean a holder's wallet contains two
 * different data models depending on which issuer sent the credential.
 */
export const CREDENTIAL_TYPE_CONTEXTS: Record<string, string[]> = {
  PatientProfileCredential: [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/jws-2020/v1',
    'https://healthwallet.example/contexts/patient-profile/v1',
  ],
  VitalSignsCredential: [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/jws-2020/v1',
    'https://healthwallet.example/contexts/vital-signs/v1',
  ],
  PrescriptionCredential: [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/jws-2020/v1',
    'https://healthwallet.example/contexts/prescription/v1',
  ],
  AppointmentDiagnosisCredential: [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/jws-2020/v1',
    'https://healthwallet.example/contexts/appointment-diagnosis/v1',
  ],
  ImmunizationCredential: [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/jws-2020/v1',
    'https://healthwallet.example/contexts/immunization/v1',
  ],
  DischargeSummaryCredential: [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/jws-2020/v1',
    'https://healthwallet.example/contexts/discharge-summary/v1',
  ],
};

export const CREDENTIAL_SCHEMA_VALIDATORS: Record<string, z.ZodSchema> = {
  PatientProfileCredential: PatientProfileSubjectSchema,
  VitalSignsCredential: VitalSignsSubjectSchema,
  PrescriptionCredential: PrescriptionSubjectSchema,
  AppointmentDiagnosisCredential: AppointmentDiagnosisSubjectSchema,
  ImmunizationCredential: ImmunizationSubjectSchema,
  DischargeSummaryCredential: DischargeSummarySubjectSchema,
};
