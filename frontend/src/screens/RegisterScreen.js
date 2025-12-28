import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
} from 'react-native';
import { authAPI } from '../services/api';

export default function RegisterScreen({ navigation }) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async () => {
    // Validation
    if (!username || !email || !password || !confirmPassword) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }

    if (password !== confirmPassword) {
      Alert.alert('Error', 'Passwords do not match');
      return;
    }

    if (password.length < 6) {
      Alert.alert('Error', 'Password must be at least 6 characters');
      return;
    }

    setLoading(true);
    try {
      const result = await authAPI.register(username, email, password);
      Alert.alert(
        'Success',
        'Account created successfully! Please login.',
        [
          {
            text: 'OK',
            onPress: () => navigation.replace('Login'),
          },
        ]
      );
    } catch (error) {
      console.error('Registration error:', error);
      Alert.alert(
        'Registration Failed',
        error.response?.data?.detail || 'Could not create account'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      style={styles.container}
    >
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.content}>
          <Text style={styles.appTitle}>🚕 FAIRRIDE</Text>
          <Text style={styles. welcomeText}>Create Account</Text>
          <Text style={styles.subtitle}>Join FairRide Today</Text>

          <View style={styles.formContainer}>
            <TextInput
              style={styles.input}
              placeholder="Username"
              placeholderTextColor="#94a3b8"
              value={username}
              onChangeText={setUsername}
              autoCapitalize="none"
              autoCorrect={false}
            />

            <TextInput
              style={styles.input}
              placeholder="Email"
              placeholderTextColor="#94a3b8"
              value={email}
              onChangeText={setEmail}
              autoCapitalize="none"
              keyboardType="email-address"
              autoCorrect={false}
            />

            <TextInput
              style={styles.input}
              placeholder="Password"
              placeholderTextColor="#94a3b8"
              value={password}
              onChangeText={setPassword}
              secureTextEntry
              autoCapitalize="none"
            />

            <TextInput
              style={styles.input}
              placeholder="Confirm Password"
              placeholderTextColor="#94a3b8"
              value={confirmPassword}
              onChangeText={setConfirmPassword}
              secureTextEntry
              autoCapitalize="none"
            />

            <TouchableOpacity
              style={[styles.button, loading && styles.buttonDisabled]}
              onPress={handleRegister}
              disabled={loading}
            >
              {loading ?  (
                <ActivityIndicator color="#fff" />
              ) : (
                <Text style={styles.buttonText}>Register</Text>
              )}
            </TouchableOpacity>
          </View>

          <TouchableOpacity
            style={styles.linkButton}
            onPress={() => navigation.navigate('Login')}
          >
            <Text style={styles. linkText}>
              Already have an account? <Text style={styles. linkTextBold}>Login</Text>
            </Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet. create({
  container: {
    flex: 1,
    backgroundColor: '#0f172a',
  },
  scrollContent:  {
    flexGrow: 1,
  },
  content: {
    flex: 1,
    justifyContent: 'center',
    padding: 20,
    paddingTop:  40,
  },
  appTitle: {
    fontSize:  48,
    fontWeight:  'bold',
    textAlign: 'center',
    color: '#f59e0b',
    marginBottom: 10,
    letterSpacing: 2,
  },
  welcomeText: {
    fontSize: 32,
    fontWeight: 'bold',
    textAlign:  'center',
    color:  '#ffffff',
    marginBottom:  8,
  },
  subtitle: {
    fontSize: 18,
    textAlign: 'center',
    marginBottom:  40,
    color: '#f59e0b',
    fontWeight: '600',
  },
  formContainer: {
    backgroundColor: '#1e293b',
    padding: 24,
    borderRadius: 20,
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width:  0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation:  8,
  },
  input: {
    backgroundColor: '#334155',
    color: '#ffffff',
    padding: 16,
    borderRadius: 12,
    marginBottom: 16,
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#475569',
  },
  button:  {
    backgroundColor: '#f59e0b',
    padding:  16,
    borderRadius:  12,
    alignItems:  'center',
    marginTop: 8,
    shadowColor: '#f59e0b',
    shadowOffset: { width:  0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation:  6,
  },
  buttonDisabled: {
    backgroundColor: '#92400e',
    opacity: 0.6,
  },
  buttonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  linkButton: {
    marginTop: 24,
    alignItems: 'center',
  },
  linkText: {
    color: '#cbd5e1',
    fontSize:  15,
  },
  linkTextBold: {
    color: '#f59e0b',
    fontWeight: 'bold',
  },
});