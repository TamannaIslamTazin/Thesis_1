/**
 * SSI Healthcare - QR Scanner Component
 *
 * Uses device camera to scan QR codes for credential offers and
 * presentation requests. Provides visual feedback and error handling.
 */

'use client';

import * as React from 'react';
import jsQR from 'jsqr';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Camera,
  CameraOff,
  QrCode,
  Loader2,
  X,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  FlipHorizontal,
  Flashlight,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { cn } from '@/lib/utils';

type ScanState = 'idle' | 'scanning' | 'processing' | 'success' | 'error';

interface QRScannerProps {
  onScan: (data: string) => Promise<void>;
  onClose?: () => void;
  className?: string;
}

export function QRScanner({ onScan, onClose, className }: QRScannerProps) {
  const videoRef = React.useRef<HTMLVideoElement>(null);
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const [state, setState] = React.useState<ScanState>('idle');
  const [error, setError] = React.useState<string | null>(null);
  const [facingMode, setFacingMode] = React.useState<'user' | 'environment'>('environment');
  const [hasFlash, setHasFlash] = React.useState(false);
  const [flashOn, setFlashOn] = React.useState(false);
  const streamRef = React.useRef<MediaStream | null>(null);

  const startCamera = React.useCallback(async () => {
    try {
      setState('scanning');
      setError(null);

      if (!navigator.mediaDevices?.getUserMedia) {
        setError('Camera not available. Use HTTPS or enter the QR data manually.');
        setState('error');
        return;
      }

      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode,
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
      });

      streamRef.current = stream;

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }

      // Check for flash capability
      const track = stream.getVideoTracks()[0];
      const capabilities = track.getCapabilities?.() as MediaTrackCapabilities & { torch?: boolean };
      setHasFlash(!!capabilities?.torch);

      // Start scanning loop
      requestAnimationFrame(scanLoop);
    } catch (err) {
      console.error('Camera error:', err);
      setState('error');
      setError('Could not access camera. Please grant permission.');
    }
  }, [facingMode]);

  const stopCamera = React.useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    setState('idle');
  }, []);

  const scanLoop = React.useCallback(() => {
    if (state !== 'scanning' || !videoRef.current || !canvasRef.current) return;

    const video = videoRef.current;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');

    if (!ctx || video.readyState !== video.HAVE_ENOUGH_DATA) {
      requestAnimationFrame(scanLoop);
      return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0);

    // Decode QR code using jsQR
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert',
    });

    if (code) {
      handleScan(code.data);
    } else {
      requestAnimationFrame(scanLoop);
    }
  }, [state]);

  const handleScan = async (data: string) => {
    setState('processing');
    stopCamera();

    try {
      await onScan(data);
      setState('success');
    } catch (err) {
      console.error('Scan processing error:', err);
      setState('error');
      setError('Could not process QR code. Please try again.');
    }
  };

  const toggleFlash = async () => {
    if (!streamRef.current) return;

    const track = streamRef.current.getVideoTracks()[0];
    try {
      await track.applyConstraints({
        advanced: [{ torch: !flashOn } as MediaTrackConstraintSet],
      });
      setFlashOn(!flashOn);
    } catch (err) {
      console.error('Flash toggle error:', err);
    }
  };

  const switchCamera = async () => {
    stopCamera();
    setFacingMode((prev) => (prev === 'user' ? 'environment' : 'user'));
  };

  React.useEffect(() => {
    return () => {
      stopCamera();
    };
  }, [stopCamera]);

  React.useEffect(() => {
    if (state === 'scanning') {
      requestAnimationFrame(scanLoop);
    }
  }, [state, scanLoop]);

  return (
    <div className={cn('relative flex flex-col items-center', className)}>
      {/* Camera view */}
      <div className="relative w-full max-w-md aspect-square rounded-2xl overflow-hidden bg-black">
        {/* Video element */}
        <video
          ref={videoRef}
          className={cn(
            'absolute inset-0 w-full h-full object-cover',
            state !== 'scanning' && 'hidden'
          )}
          playsInline
          muted
        />
        
        {/* Hidden canvas for processing */}
        <canvas ref={canvasRef} className="hidden" />

        {/* Scanning overlay */}
        <AnimatePresence>
          {state === 'scanning' && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 flex items-center justify-center"
            >
              {/* Scanning frame */}
              <div className="relative w-64 h-64">
                {/* Corner brackets */}
                <div className="absolute top-0 left-0 w-8 h-8 border-t-4 border-l-4 border-primary rounded-tl-lg" />
                <div className="absolute top-0 right-0 w-8 h-8 border-t-4 border-r-4 border-primary rounded-tr-lg" />
                <div className="absolute bottom-0 left-0 w-8 h-8 border-b-4 border-l-4 border-primary rounded-bl-lg" />
                <div className="absolute bottom-0 right-0 w-8 h-8 border-b-4 border-r-4 border-primary rounded-br-lg" />
                
                {/* Scanning line */}
                <motion.div
                  className="absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent"
                  animate={{ top: ['0%', '100%', '0%'] }}
                  transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Idle state */}
        {state === 'idle' && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-muted">
            <QrCode className="w-16 h-16 text-muted-foreground mb-4" />
            <p className="text-muted-foreground mb-4">Ready to scan</p>
            <PremiumButton variant="premium" onClick={startCamera}>
              <Camera className="w-4 h-4 mr-2" />
              Start Camera
            </PremiumButton>
          </div>
        )}

        {/* Processing state */}
        {state === 'processing' && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-background/80 backdrop-blur-sm">
            <Loader2 className="w-12 h-12 text-primary animate-spin mb-4" />
            <p className="text-foreground">Processing...</p>
          </div>
        )}

        {/* Success state */}
        {state === 'success' && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-background/80 backdrop-blur-sm">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mb-4"
            >
              <CheckCircle2 className="w-8 h-8 text-emerald-500" />
            </motion.div>
            <p className="text-foreground font-medium">QR Code Scanned!</p>
          </div>
        )}

        {/* Error state */}
        {state === 'error' && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-background/80 backdrop-blur-sm">
            <div className="w-16 h-16 rounded-full bg-red-500/20 flex items-center justify-center mb-4">
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
            <p className="text-foreground font-medium mb-2">Scan Failed</p>
            <p className="text-sm text-muted-foreground mb-4">{error}</p>
            <PremiumButton variant="outline" onClick={startCamera}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Try Again
            </PremiumButton>
          </div>
        )}

        {/* Controls overlay */}
        {state === 'scanning' && (
          <div className="absolute bottom-4 left-0 right-0 flex items-center justify-center gap-4">
            <button
              onClick={switchCamera}
              className="p-3 rounded-full bg-black/50 text-foreground hover:bg-black/70 transition-colors"
            >
              <FlipHorizontal className="w-5 h-5" />
            </button>
            {hasFlash && (
              <button
                onClick={toggleFlash}
                className={cn(
                  'p-3 rounded-full transition-colors',
                  flashOn
                    ? 'bg-yellow-500 text-black'
                    : 'bg-black/50 text-foreground hover:bg-black/70'
                )}
              >
                <Flashlight className="w-5 h-5" />
              </button>
            )}
            <button
              onClick={stopCamera}
              className="p-3 rounded-full bg-black/50 text-foreground hover:bg-black/70 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        )}

        {/* Close button */}
        {onClose && (
          <button
            onClick={onClose}
            className="absolute top-4 right-4 p-2 rounded-full bg-black/50 text-foreground hover:bg-black/70 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Instructions */}
      <div className="mt-6 text-center">
        <p className="text-muted-foreground">
          Point your camera at a QR code to scan
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          Supports credential offers and presentation requests
        </p>
      </div>
    </div>
  );
}

/** Manual QR code input as fallback */
export function ManualQRInput({
  onSubmit,
  className,
}: {
  onSubmit: (data: string) => void;
  className?: string;
}) {
  const [value, setValue] = React.useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (value.trim()) {
      onSubmit(value.trim());
    }
  };

  return (
    <form onSubmit={handleSubmit} className={cn('space-y-4', className)}>
      <div>
        <label className="text-sm font-medium text-foreground mb-2 block">
          Or enter QR code data manually
        </label>
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Paste credential offer or presentation request URL..."
          className="w-full h-24 px-4 py-3 bg-muted border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
        />
      </div>
      <PremiumButton
        type="submit"
        variant="outline"
        disabled={!value.trim()}
        fullWidth
      >
        Submit
      </PremiumButton>
    </form>
  );
}
