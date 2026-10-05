/**
 * SSI Healthcare Mobile - App Entry Point
 *
 * Sets up React Navigation with tab-based navigation
 * for the patient wallet app. Includes service initialization
 * for push notifications, biometric auth, and secure storage.
 */

import React, { useEffect, useCallback, useRef } from 'react';
// Core RN Linking, not expo-linking: the dependency is already here and adding
// one to read a URL would be a poor trade.
import { Linking } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { NavigationContainer, DefaultTheme } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { SafeAreaProvider, useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';

import HomeScreen from './src/screens/HomeScreen';
import CredentialsScreen from './src/screens/CredentialsScreen';
import CredentialsByCategoryScreen from './src/screens/CredentialsByCategoryScreen';
import CredentialDetailScreen from './src/screens/CredentialDetailScreen';
import ConsentScreen from './src/screens/ConsentScreen';
import EmergencyAccessScreen from './src/screens/EmergencyAccessScreen';
import MedicineBalanceScreen from './src/screens/MedicineBalanceScreen';
import ActivityLogScreen from './src/screens/ActivityLogScreen';
import SettingsScreen from './src/screens/SettingsScreen';
import OnboardingScreen from './src/screens/OnboardingScreen';
import QRScannerScreen from './src/screens/QRScannerScreen';
import AuthScreen from './src/screens/AuthScreen';
import VerifierScreen from './src/screens/VerifierScreen';
import NewDeviceRestoreScreen from './src/screens/NewDeviceRestoreScreen';
import DocumentSubmissionScreen from './src/screens/DocumentSubmissionScreen';
import SubmissionStatusScreen from './src/screens/SubmissionStatusScreen';
import PassphraseSetupScreen from './src/screens/PassphraseSetupScreen';

import { AuthProvider, useAuth, SettingsProvider } from './src/contexts';
import { colors } from './src/theme';
import { useCredentialStore } from './src/store';
import { useIncomingRequestStore } from './src/store/incomingRequestStore';
import { parseDeepLink } from './src/services/deepLinks';
import { parseChallenge } from './src/services/presentationOffer';
import { usePresentationShareStore } from './src/store/presentationShareStore';
import { IncomingRequestHost } from './src/components/IncomingRequestHost';
import { AppAlertHost } from './src/components/AppAlertHost';
import { offersVerifierMode } from './src/store/professionalLicence';
import {
  registerForegroundDrain,
  registerSyncTask,
  runBackgroundTaskProbe,
} from './src/background/tasks';
import type {
  CredentialStackParamList,
  RootStackParamList,
  RootTabParamList,
} from './src/types';
import { 
  pushNotificationService, 
  biometricAuthService, 
  secureStorage,
  STORAGE_KEYS 
} from './src/services';

const Tab = createBottomTabNavigator<RootTabParamList>();
const CredentialStack = createNativeStackNavigator<CredentialStackParamList>();
const RootStack = createNativeStackNavigator<RootStackParamList>();

// The navigator's own background, repainted with the app's.
//
// The top inset is applied once, on the navigators (`sceneStyle.paddingTop`
// below, and `contentStyle.paddingTop` on the root stack) — and that inset
// reveals whatever the NAVIGATOR paints behind it, which is React Navigation's
// default #F2F2F2. Against this app's #F8FAFC surfaces that reads as a grey
// band under the status bar on every screen. Measured 19 Sep 2026 with the
// device screenshot: rows y=0–190 are rgb(242,242,242), the app's own
// background begins only at y=192. Painting the theme background removes the
// seam without each screen having to own a strip above its content.
const navigationTheme = {
  ...DefaultTheme,
  colors: { ...DefaultTheme.colors, background: colors.background.primary },
};

// -- Credential Stack Navigator --

function CredentialsStackNavigator() {
  return (
    // NO NAVIGATOR HEADER ANYWHERE.
    //
    // Every screen draws its own title inside its scroll view, which is what
    // lets the title scroll away and gives the content the full height. A
    // navigator header on top of that produced two titles on one screen, and
    // on the subscreens it was the only thing left of the old pattern.
    //
    // `title` is kept on each screen because it is what the tab bar and the
    // back-navigation accessibility label read; it just no longer draws a bar.
    <CredentialStack.Navigator
      screenOptions={{ headerShown: false }}
    >
      <CredentialStack.Screen
        name="CredentialsList"
        component={CredentialsScreen}
        options={{ title: 'My Credentials' }}
      />
      <CredentialStack.Screen
        name="CredentialsByCategory"
        component={CredentialsByCategoryScreen}
        options={{ title: 'Folder' }}
      />
      <CredentialStack.Screen
        name="CredentialDetail"
        component={CredentialDetailScreen}
        options={{ title: 'Credential Details' }}
      />
    </CredentialStack.Navigator>
  );
}

// -- Tab Navigator --

function MainTabs() {
  const credentials = useCredentialStore((state) => state.credentials);
  const showVerifier = offersVerifierMode(credentials);
  // The Android system navigation bar sits under the tab bar when it is on.
  // Without this the last row of labels is behind it and the tabs are hard to
  // hit. Gesture navigation reports a small inset, three-button a large one, so
  // the value has to come from the system and cannot be a constant.
  const insets = useSafeAreaInsets();

  return (
    // THE TOP INSET IS APPLIED ONCE, HERE, FOR EVERY TAB SCREEN.
    //
    // It used to be each screen's own job, and six of fifteen did it. The
    // other nine drew their first line under the clock, which is how the
    // credentials list ended up with its heading behind the status bar. A
    // per-screen convention that must be remembered on every new screen is a
    // convention that will be missed; this cannot be.
    //
    // Screens presented from the ROOT stack are handled separately below,
    // because the scanner is deliberately full-bleed.
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: keyof typeof Ionicons.glyphMap = 'home';

          switch (route.name) {
            case 'HomeTab':
              iconName = focused ? 'home' : 'home-outline';
              break;
            case 'CredentialsTab':
              iconName = focused ? 'folder' : 'folder-outline';
              break;
            case 'ScanTab':
              iconName = focused ? 'scan' : 'scan-outline';
              break;
            case 'VerifyTab':
              iconName = focused ? 'shield-checkmark' : 'shield-checkmark-outline';
              break;
            case 'ConsentTab':
              iconName = focused ? 'shield-checkmark' : 'shield-checkmark-outline';
              break;
            case 'MedicineBalanceTab':
              iconName = focused ? 'medkit' : 'medkit-outline';
              break;
            case 'SettingsTab':
              iconName = focused ? 'settings' : 'settings-outline';
              break;
          }

          return <Ionicons name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: colors.ui.tabActive,
        tabBarInactiveTintColor: colors.ui.tabInactive,
        tabBarStyle: {
          backgroundColor: colors.surface.card,
          borderTopColor: colors.border.default,
          paddingBottom: 8 + insets.bottom,
          paddingTop: 8,
          height: 65 + insets.bottom,
        },
        tabBarLabelStyle: {
          // 11pt truncated "Credentials" and "Emergency" to "Credenti…" and
          // "Emergen…" across six tabs on a 1080px screen. The labels are the
          // only thing naming these destinations, so they are not abbreviable.
          fontSize: 10,
          fontWeight: '600',
        },
        tabBarItemStyle: { paddingHorizontal: 2 },
        // NO top inset here. Tab screens live INSIDE the root stack, which
        // already pads its scene by `rootInsets.top` — so this was a SECOND
        // application of the same inset, and every tab screen started 2x the
        // status bar (68dp) below the top. Measured 19 Sep 2026: insets.top
        // and RN's StatusBar.currentHeight both 34.18dp, content at ~190px.
        headerStyle: { backgroundColor: colors.surface.card },
        headerTintColor: colors.text.primary,
        headerTitleStyle: { fontWeight: '700' },
      })}
    >
      <Tab.Screen
        name="HomeTab"
        component={HomeScreen}
        // No header. The screen opens with its own greeting and the holder's
        // name, so a bar reading "SSI Healthcare" above it named the app to
        // someone already inside it and cost a fifth of the viewport.
        options={{ title: 'Home', headerShown: false }}
      />
      <Tab.Screen
        name="CredentialsTab"
        component={CredentialsStackNavigator}
        // 'Credentials' was the only label wide enough to truncate to
        // 'Credentia...' at six tabs. The tab label is the only thing naming
        // this destination, so it is shortened rather than clipped.
        options={{ title: 'Cards', headerShown: false }}
      />
      <Tab.Screen
        name="ScanTab"
        component={QRScannerScreen}
        options={{ 
          title: 'Scan', 
          headerShown: false,
          tabBarStyle: { display: 'none' },
        }}
      />
      {/*
        VERIFIER MODE IS GATED ON A CREDENTIAL, NEVER ON THE GROUP THE USER
        PICKED AT ONBOARDING. That self-declaration is a routing hint and is not
        evidence of anything; routing on it here would make R4's claim false in
        the client even while it held in the backend. `offersVerifierMode` reads
        professional licence credentials and has no parameter through which a
        profile field could arrive.

        The tab APPEARS once credentials load rather than on first paint. The
        store hydrates from a five-minute cache, so it is immediate on every
        launch after the first; on a genuinely cold start it follows HomeScreen's
        fetch. Rendering the tab optimistically and hiding it again would be
        worse — a control that vanishes reads as a fault.
      */}
      {showVerifier ? (
        <Tab.Screen
          name="VerifyTab"
          component={VerifierScreen}
          options={{ title: 'Verify', headerShown: false }}
        />
      ) : null}
      <Tab.Screen
        name="ConsentTab"
        component={ConsentScreen}
        // Header removed; the screen renders its own title inline. See ScreenTitle.
        options={{ title: 'Consent', headerShown: false }}
      />
      <Tab.Screen
        name="MedicineBalanceTab"
        component={MedicineBalanceScreen}
        // Header removed; the screen renders its own title inline. See ScreenTitle.
        // This tab used to be Emergency; emergency access now lives under Consent.
        options={{ title: 'Medicines', headerShown: false }}
      />
      <Tab.Screen
        name="SettingsTab"
        component={SettingsScreen}
        // Header removed; the screen renders its own title inline. See ScreenTitle.
        options={{ title: 'Settings', headerShown: false }}
      />
    </Tab.Navigator>
  );
}

// -- Root Navigator with Auth --

function RootNavigator() {
  const rootInsets = useSafeAreaInsets();
  const { isAuthenticated, isInitialized, user } = useAuth();
  const [isOnboarded, setIsOnboarded] = React.useState(false);
  const [isLoading, setIsLoading] = React.useState(true);
  // Null until read. Three states, because "not yet known" must not be treated
  // as "not set up" — doing so would flash the enrolment gate at every launch.
  const [hasRecovery, setHasRecovery] = React.useState<boolean | null>(null);

  useEffect(() => {
    async function checkOnboarding() {
      try {
        const onboarded = await secureStorage.get(STORAGE_KEYS.ONBOARDING_COMPLETE);
        if (onboarded === 'true') {
          setIsOnboarded(true);
        }
      } catch (error) {
        console.error('[App] Failed to check onboarding state:', error);
      } finally {
        setIsLoading(false);
      }
    }

    checkOnboarding();
  }, []);

  // Recovery is re-checked whenever the session changes, because the answer
  // belongs to the account and not to the install: signing out and into a
  // different account must re-gate.
  useEffect(() => {
    let cancelled = false;

    async function checkRecovery() {
      if (!isAuthenticated) {
        if (!cancelled) setHasRecovery(null);
        return;
      }
      try {
        const stored = await secureStorage.get(STORAGE_KEYS.RECOVERY_HANDLE);
        // The record names the account it belongs to. Anything else — absent,
        // unparseable, or another user's — counts as "no recovery" and re-gates,
        // because a handle inherited from a previous session on this handset let
        // a new account walk straight past enrolment.
        let owned = false;
        if (stored) {
          try {
            const parsed = JSON.parse(stored) as { userId?: string; handle?: string };
            owned = Boolean(parsed.handle) && parsed.userId === user?.id;
          } catch {
            owned = false;
          }
        }
        if (!cancelled) setHasRecovery(owned);
      } catch (error) {
        console.error('[App] Failed to read recovery state:', error);
        // Fail towards the gate. Showing setup to someone who has already done
        // it costs them a screen they can complete again; skipping it for
        // someone who has not costs them the wallet.
        if (!cancelled) setHasRecovery(false);
      }
    }

    checkRecovery();
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, user?.id]);

  const handleOnboardingComplete = useCallback(async () => {
    try {
      await secureStorage.set(STORAGE_KEYS.ONBOARDING_COMPLETE, 'true');
      setIsOnboarded(true);
    } catch (error) {
      console.error('[App] Failed to save onboarding state:', error);
      setIsOnboarded(true);
    }
  }, []);

  const handleRecoveryComplete = useCallback(() => {
    setHasRecovery(true);
  }, []);

  // Gate on initialisation only. Gating on `isLoading` tore the navigator down
  // mid-login, remounting AuthScreen with fresh state and swallowing the error.
  if (isLoading || !isInitialized) {
    return null;
  }

  // Signed in, but the recovery answer has not come back yet. Rendering either
  // branch now would show a screen we may immediately replace.
  if (isAuthenticated && hasRecovery === null) {
    return null;
  }

  return (
    <RootStack.Navigator
      screenOptions={{
        headerShown: false,
        // THE ONLY place the top inset is applied. Every root-stack screen —
        // auth, restore, modals, and the tab container itself — is padded
        // exactly once here; `Scanner` overrides it back to zero because a
        // camera preview must reach the top of the display. Re-adding it on a
        // nested navigator doubles it (see the tab navigator's note).
        contentStyle: { paddingTop: rootInsets.top },
      }}
    >
      {!isOnboarded ? (
        <RootStack.Screen name="Onboarding">
          {(props) => (
            <OnboardingScreen
              {...props}
              onComplete={handleOnboardingComplete}
            />
          )}
        </RootStack.Screen>
      ) : !isAuthenticated ? (
        <>
          <RootStack.Screen name="Auth" component={AuthScreen} />
          <RootStack.Screen
            name="NewDeviceRestore"
            component={NewDeviceRestoreScreen}
            options={{
              title: 'Restore your wallet',
              headerStyle: { backgroundColor: colors.surface.card },
              headerTintColor: colors.text.primary,
              headerTitleStyle: { fontWeight: '700' },
            }}
          />
        </>
      ) : !hasRecovery ? (
        // Enrolment is not finished until the account can be recovered. This is
        // the only route out of registration: the wallet holds material that
        // nothing else can reconstruct, so reaching it before recovery exists
        // would create an account that is one lost handset away from gone.
        // Distinct route name from the settings copy of this screen. Sharing one
        // name kept the route mounted when `hasRecovery` flipped, so the branch
        // swap re-rendered the settings variant in place instead of falling
        // through to the wallet.
        <RootStack.Screen
          name="EnrolmentRecovery"
          options={{
            title: 'Account Recovery',
            headerStyle: { backgroundColor: colors.surface.card },
            headerTintColor: colors.text.primary,
            headerTitleStyle: { fontWeight: '700' },
            headerBackVisible: false,
            gestureEnabled: false,
          }}
        >
          {() => <PassphraseSetupScreen onComplete={handleRecoveryComplete} />}
        </RootStack.Screen>
      ) : (
        <>
          <RootStack.Screen name="MainTabs" component={MainTabs} />
          <RootStack.Screen
            name="Scanner"
            component={QRScannerScreen}
            options={{
              presentation: 'fullScreenModal',
              // Full-bleed: the camera preview reaches the top of the display.
              contentStyle: { paddingTop: 0 },
              animation: 'slide_from_bottom',
            }}
          />
          <RootStack.Screen
            name="ActivityLog"
            component={ActivityLogScreen}
            options={{
              title: 'Activity Log',
              headerStyle: { backgroundColor: colors.surface.card },
              headerTintColor: colors.text.primary,
              headerTitleStyle: { fontWeight: '700' },
              presentation: 'card',
            }}
          />
          <RootStack.Screen
            name="EmergencyAccess"
            component={EmergencyAccessScreen}
            options={{
              title: 'Emergency Access',
              headerStyle: { backgroundColor: colors.surface.card },
              headerTintColor: colors.text.primary,
              headerTitleStyle: { fontWeight: '700' },
            }}
          />
          <RootStack.Screen
            name="DocumentSubmission"
            component={DocumentSubmissionScreen}
            options={{
              title: 'Submit Documents',
              headerStyle: { backgroundColor: colors.surface.card },
              headerTintColor: colors.text.primary,
              headerTitleStyle: { fontWeight: '700' },
            }}
          />
          <RootStack.Screen
            name="SubmissionStatus"
            component={SubmissionStatusScreen}
            options={{
              title: 'My Submissions',
              headerStyle: { backgroundColor: colors.surface.card },
              headerTintColor: colors.text.primary,
              headerTitleStyle: { fontWeight: '700' },
            }}
          />
          <RootStack.Screen
            name="PassphraseSetup"
            component={PassphraseSetupScreen}
            options={{
              title: 'Account Recovery',
              headerStyle: { backgroundColor: colors.surface.card },
              headerTintColor: colors.text.primary,
              headerTitleStyle: { fontWeight: '700' },
            }}
          />
        </>
      )}
    </RootStack.Navigator>
  );
}

// -- Root App --

/**
 * Deliver deep links to the authorization sheet.
 *
 * Two sources, both required. `getInitialURL` covers a COLD start — the app was
 * not running when the link was tapped, which is the ordinary case for "Sign in
 * with SSI" from a browser. The `url` event covers a warm one. Handling only the
 * second is the classic version of this bug: it works whenever you test it,
 * because by then the app is already open.
 *
 * An unreadable link does nothing at all. Opening a sheet that says "Unknown"
 * for every stray link the OS routes here would train the holder to dismiss the
 * exact surface that must hold their attention.
 */
function DeepLinkListener() {
  const present = useIncomingRequestStore((state) => state.present);
  const { isAuthenticated } = useAuth();
  // A link that arrives while the holder is signed out is HELD here, not shown.
  const heldUrl = useRef<string | null>(null);

  const route = useCallback(
    (url: string) => {
      // A verifier's answer to a holder-initiated offer arrives the same way
      // an HMS request does. It is not an authorization request, so it is
      // routed to the share session rather than the request sheet.
      if (parseChallenge(url)) {
        usePresentationShareStore.getState().setPendingChallenge(url);
        return;
      }
      const request = parseDeepLink(url);
      if (request) present(request, 'link');
    },
    [present],
  );

  useEffect(() => {
    let cancelled = false;

    const handle = (url: string | null) => {
      if (!url || cancelled) return;
      // NOTHING FIRES BEFORE THE HOLDER IS AUTHENTICATED. The request sheet
      // names a verifier and offers to share credentials; over the login
      // screen it invites a decision the holder cannot yet make, and it tells
      // anyone holding the unlocked phone who is asking. Hold the link and
      // route it the moment sign-in completes.
      if (!isAuthenticated) {
        heldUrl.current = url;
        return;
      }
      route(url);
    };

    void Linking.getInitialURL().then(handle);
    const subscription = Linking.addEventListener('url', (event: { url: string }) =>
      handle(event.url),
    );

    return () => {
      cancelled = true;
      subscription.remove();
    };
  }, [isAuthenticated, route]);

  // Release the held link once the holder is inside the wallet.
  useEffect(() => {
    if (!isAuthenticated || !heldUrl.current) return;
    const url = heldUrl.current;
    heldUrl.current = null;
    route(url);
  }, [isAuthenticated, route]);

  return null;
}

export default function App() {
  useEffect(() => {
    let stopForegroundDrain: (() => void) | undefined;

    async function initializeServices() {
      try {
        // PUSH NOTIFICATIONS ARE NOT ENABLED, and the app should stop
        // pretending otherwise.
        //
        // The delivery side was never built: no server sends anything, and the
        // client has no Firebase configuration, so initialising it did nothing
        // except raise a red error banner over the interface on every launch
        // reading "Default FirebaseApp is not initialized in this process".
        // That banner sat on top of the emergency alarm.
        //
        // It is left dormant rather than deleted: the service and its listeners
        // are intact and this is the single line that starts them. The screens
        // that would depend on it already say so in words. The break-glass
        // explanation, for one, tells the holder that alerting is not built and
        // that they should check the screen, which is true and stays true.
        //
        // NOTHING silently substitutes for it. Nowhere in the app claims a
        // notification will arrive.

        const biometricAvailable = await biometricAuthService.isAvailable();
        if (__DEV__) console.log('[App] Biometric available:', biometricAvailable);

        await registerSyncTask();
        stopForegroundDrain = registerForegroundDrain();

        if (__DEV__) {
          // One-shot probe for the on-device backend's crypto runtime. See
          // src/probes/workletCryptoProbe.ts; delete both lines with the file.
          const { runWorkletCryptoProbe } = require('./src/probes/workletCryptoProbe');
          runWorkletCryptoProbe();

          // One-shot probe for the encrypted wallet database (SQLCipher). See
          // src/probes/sqlCipherProbe.ts; delete both lines with the file.
          const { runSqlCipherProbe } = require('./src/probes/sqlCipherProbe');
          runSqlCipherProbe();

          runBackgroundTaskProbe();

          const { runDatastoreBackupProbe } = require('./src/probes/datastoreBackupProbe');
          runDatastoreBackupProbe();
        }
      } catch (error) {
        console.error('[App] Initialization error:', error);
      }
    }

    initializeServices();

    return () => {
      stopForegroundDrain?.();
      pushNotificationService.cleanup();
    };
  }, []);

  return (
    <SafeAreaProvider>
      <SettingsProvider>
        <AuthProvider>
          <NavigationContainer theme={navigationTheme}>
            <StatusBar style="dark" />
            <RootNavigator />
            {/* Above the navigator, so a link that arrives while the holder is
                on any screen — or while the app was closed — still reaches the
                authorization sheet. */}
            <IncomingRequestHost />
        <AppAlertHost />
            <DeepLinkListener />
          </NavigationContainer>
        </AuthProvider>
      </SettingsProvider>
    </SafeAreaProvider>
  );
}
