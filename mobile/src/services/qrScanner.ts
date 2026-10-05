/**
 * SSI Healthcare Mobile - QR Scanner Service
 * 
 * Handles QR code scanning for OID4VCI credential offers and
 * OID4VP presentation requests.
 */

import { CameraView, useCameraPermissions, BarcodeScanningResult } from 'expo-camera';
import { z } from 'zod';

// QR code content types
export enum QRCodeType {
  CREDENTIAL_OFFER = 'credential_offer',
  PRESENTATION_REQUEST = 'presentation_request',
  /** A verifier's answer to a holder-initiated presentation offer. */
  PRESENTATION_CHALLENGE = 'presentation_challenge',
  DID = 'did',
  UNKNOWN = 'unknown',
}

export interface ParsedQRCode {
  type: QRCodeType;
  rawData: string;
  parsedData?: unknown;
  error?: string;
}

// OID4VCI Credential Offer URI pattern
const CREDENTIAL_OFFER_URI_PATTERN = /^openid-credential-offer:\/\//;

// OID4VP Presentation Request URI patterns
const PRESENTATION_REQUEST_URI_PATTERNS = [
  /^openid-vp:\/\//,
  /^openid4vp:\/\//,
];

// DID pattern
const DID_PATTERN = /^did:[a-z0-9]+:[a-zA-Z0-9._%-]+/;

class QRScannerService {
  /**
   * Parse QR code content and determine its type.
   */
  parseQRCode(data: string): ParsedQRCode {
    const trimmedData = data.trim();

    // A verifier's answer to a holder-initiated offer. Accepted here so the
    // same camera path serves both directions of the exchange; the payload is
    // validated against the pending offer by the share sheet that reads it.
    // Scheme-agnostic on purpose: the installed dev client's scheme is
    // `exp+ssi-healthcare-wallet://` (steno #421), and the payload is read out
    // of whatever wrapper carried it. Full validation is the share sheet's job.
    if (/^[a-z][a-z0-9+.-]*:\/\/[^?]*presentation-challenge\?/i.test(trimmedData)) {
      return { type: QRCodeType.PRESENTATION_CHALLENGE, rawData: trimmedData };
    }

    // Check for OID4VCI Credential Offer
    if (CREDENTIAL_OFFER_URI_PATTERN.test(trimmedData)) {
      return this.parseCredentialOffer(trimmedData);
    }

    // Check for OID4VP Presentation Request
    for (const pattern of PRESENTATION_REQUEST_URI_PATTERNS) {
      if (pattern.test(trimmedData)) {
        return this.parsePresentationRequest(trimmedData);
      }
    }

    // Check for DID
    if (DID_PATTERN.test(trimmedData)) {
      return {
        type: QRCodeType.DID,
        rawData: trimmedData,
        parsedData: { did: trimmedData },
      };
    }

    // Try parsing as JSON (could be a direct credential offer or request)
    try {
      const parsed = JSON.parse(trimmedData);
      
      // Check if it's a credential offer
      if (parsed.credential_issuer || parsed.credentialIssuer) {
        return {
          type: QRCodeType.CREDENTIAL_OFFER,
          rawData: trimmedData,
          parsedData: parsed,
        };
      }
      
      // Check if it's a presentation request
      if (parsed.presentation_definition || parsed.requestedCredentials) {
        return {
          type: QRCodeType.PRESENTATION_REQUEST,
          rawData: trimmedData,
          parsedData: parsed,
        };
      }
    } catch {
      // Not valid JSON
    }

    return {
      type: QRCodeType.UNKNOWN,
      rawData: trimmedData,
      error: 'Unable to determine QR code type',
    };
  }

  /**
   * Parse OID4VCI credential offer URI.
   */
  private parseCredentialOffer(uri: string): ParsedQRCode {
    try {
      const url = new URL(uri);
      
      // Check for inline credential_offer parameter
      const offerParam = url.searchParams.get('credential_offer');
      if (offerParam) {
        const decoded = decodeURIComponent(offerParam);
        const parsed = JSON.parse(decoded);
        return {
          type: QRCodeType.CREDENTIAL_OFFER,
          rawData: uri,
          parsedData: parsed,
        };
      }

      // Check for credential_offer_uri (requires additional fetch)
      const offerUri = url.searchParams.get('credential_offer_uri');
      if (offerUri) {
        return {
          type: QRCodeType.CREDENTIAL_OFFER,
          rawData: uri,
          parsedData: { 
            requiresFetch: true, 
            offerUri: decodeURIComponent(offerUri) 
          },
        };
      }

      return {
        type: QRCodeType.CREDENTIAL_OFFER,
        rawData: uri,
        error: 'Invalid credential offer URI: missing credential_offer or credential_offer_uri parameter',
      };
    } catch (error) {
      return {
        type: QRCodeType.CREDENTIAL_OFFER,
        rawData: uri,
        error: error instanceof Error ? error.message : 'Failed to parse credential offer',
      };
    }
  }

  /**
   * Parse OID4VP presentation request URI.
   */
  private parsePresentationRequest(uri: string): ParsedQRCode {
    try {
      // Replace openid-vp:// or openid4vp:// with https:// for URL parsing
      const httpsUri = uri.replace(/^openid4?-vp:/, 'https:');
      const url = new URL(httpsUri);

      // Check for inline request parameter (JWT)
      const requestParam = url.searchParams.get('request');
      if (requestParam) {
        // Decode JWT payload (without verification - that happens on backend)
        const payload = this.decodeJwtPayload(requestParam);
        return {
          type: QRCodeType.PRESENTATION_REQUEST,
          rawData: uri,
          parsedData: {
            jwt: requestParam,
            payload,
          },
        };
      }

      // Check for request_uri (requires additional fetch)
      const requestUri = url.searchParams.get('request_uri');
      if (requestUri) {
        return {
          type: QRCodeType.PRESENTATION_REQUEST,
          rawData: uri,
          parsedData: {
            requiresFetch: true,
            requestUri: decodeURIComponent(requestUri),
          },
        };
      }

      // Check for presentation_definition parameter
      const presentationDef = url.searchParams.get('presentation_definition');
      if (presentationDef) {
        return {
          type: QRCodeType.PRESENTATION_REQUEST,
          rawData: uri,
          parsedData: {
            presentation_definition: JSON.parse(decodeURIComponent(presentationDef)),
            nonce: url.searchParams.get('nonce'),
            state: url.searchParams.get('state'),
            response_uri: url.searchParams.get('response_uri'),
          },
        };
      }

      return {
        type: QRCodeType.PRESENTATION_REQUEST,
        rawData: uri,
        error: 'Invalid presentation request URI: missing required parameters',
      };
    } catch (error) {
      return {
        type: QRCodeType.PRESENTATION_REQUEST,
        rawData: uri,
        error: error instanceof Error ? error.message : 'Failed to parse presentation request',
      };
    }
  }

  /**
   * Decode JWT payload without verification.
   * Verification is done by the backend.
   */
  private decodeJwtPayload(jwt: string): Record<string, unknown> {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const payload = parts[1];
    // Handle base64url encoding
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(base64);
    return JSON.parse(decoded);
  }

  /**
   * Validate barcode scanning result.
   */
  validateScanResult(result: BarcodeScanningResult): ParsedQRCode | null {
    if (!result.data) {
      return null;
    }

    return this.parseQRCode(result.data);
  }

  /**
   * Get user-friendly description of QR code type.
   */
  getTypeDescription(type: QRCodeType): string {
    switch (type) {
      case QRCodeType.CREDENTIAL_OFFER:
        return 'Credential Offer';
      case QRCodeType.PRESENTATION_REQUEST:
        return 'Verification Request';
      case QRCodeType.PRESENTATION_CHALLENGE:
        return 'Verifier Response';
      case QRCodeType.DID:
        return 'Decentralized Identifier';
      case QRCodeType.UNKNOWN:
      default:
        return 'Unknown QR Code';
    }
  }

  /**
   * Get action button text for QR code type.
   */
  getActionText(type: QRCodeType): string {
    switch (type) {
      case QRCodeType.CREDENTIAL_OFFER:
        return 'Receive Credential';
      case QRCodeType.PRESENTATION_REQUEST:
        return 'Share Credentials';
      case QRCodeType.PRESENTATION_CHALLENGE:
        return 'Answer Request';
      case QRCodeType.DID:
        return 'Add Contact';
      case QRCodeType.UNKNOWN:
      default:
        return 'View Details';
    }
  }
}

// Export singleton instance
export const qrScannerService = new QRScannerService();

// Export the camera permissions hook for use in components
export { useCameraPermissions };
