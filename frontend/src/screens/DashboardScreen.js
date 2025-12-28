import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ActivityIndicator,
  ScrollView,
} from 'react-native';
import { tripAPI, authAPI } from '../services/api';

export default function DashboardScreen({ navigation }) {
  const [origin, setOrigin] = useState('');
  const [destination, setDestination] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRequestRide = async () => {
    if (!origin || !destination) {
      Alert.alert('Error', 'Please enter origin and destination');
      return;
    }

    setLoading(true);
    try {
      const trip = await tripAPI.createTrip(origin, destination);
      Alert.alert('Success', 'Trip request created! ');
      
      navigation.navigate('PriceComparison', {
        tripId: trip. trip_id,
        origin: trip.origin,
        destination: trip.destination,
      });
    } catch (error) {
      console.error('Trip creation error:', error);
      Alert.alert(
        'Request Failed',
        error.response?. data?.detail || 'Failed to create trip request'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    Alert.alert(
      'Logout',
      'Are you sure you want to logout?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Logout',
          style: 'destructive',
          onPress: async () => {
            try {
              await authAPI.logout();
              navigation.replace('Login');
            } catch (error) {
              console.error('Logout error:', error);
              navigation.replace('Login');
            }
          },
        },
      ]
    );
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.appTitle}>🚕 FAIRRIDE</Text>
        <Text style={styles.title}>Request a Ride</Text>
        <Text style={styles.subtitle}>Find the best deal for your journey</Text>

        <View style={styles.formContainer}>
          <Text style={styles.label}>📍 Pickup Location</Text>
          <TextInput
            style={styles.input}
            placeholder="e.g.  Times Square, New York"
            placeholderTextColor="#94a3b8"
            value={origin}
            onChangeText={setOrigin}
            autoCapitalize="words"
          />

          <Text style={styles.label}>🎯 Drop-off Location</Text>
          <TextInput
            style={styles. input}
            placeholder="e. g. Central Park, New York"
            placeholderTextColor="#94a3b8"
            value={destination}
            onChangeText={setDestination}
            autoCapitalize="words"
          />

          <TouchableOpacity
            style={[styles.button, loading && styles. buttonDisabled]}
            onPress={handleRequestRide}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <Text style={styles.buttonText}>Compare Prices 💰</Text>
            )}
          </TouchableOpacity>
        </View>

        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>✨ How it works</Text>
          <Text style={styles.infoText}>
            1. Enter your pickup and drop-off locations{'\n'}
            2. We'll fetch prices from all providers{'\n'}
            3. See the best price highlighted{'\n'}
            4. All data is encrypted and secure 🔒
          </Text>
        </View>

        <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
          <Text style={styles.logoutText}>Logout</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f172a',
  },
  content: {
    padding: 20,
    paddingTop: 20,
  },
  appTitle: {
    fontSize: 40,
    fontWeight: 'bold',
    textAlign: 'center',
    color: '#f59e0b',
    marginTop: 20,
    marginBottom: 20,
    letterSpacing: 2,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 10,
    color: '#ffffff',
  },
  subtitle:  {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 30,
    color: '#94a3b8',
  },
  formContainer: {
    backgroundColor: '#1e293b',
    padding: 20,
    borderRadius: 20,
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity:  0.3,
    shadowRadius: 8,
    elevation: 8,
  },
  label: {
    fontSize:  16,
    fontWeight:  '600',
    marginBottom: 8,
    color: '#f59e0b',
  },
  input: {
    backgroundColor: '#334155',
    color: '#ffffff',
    padding:  15,
    borderRadius: 12,
    marginBottom: 20,
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#475569',
  },
  button: {
    backgroundColor: '#f59e0b',
    padding: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 10,
    shadowColor: '#f59e0b',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 6,
  },
  buttonDisabled: {
    backgroundColor: '#92400e',
    opacity: 0.6,
  },
  buttonText: {
    color: '#ffffff',
    fontSize:  18,
    fontWeight: 'bold',
  },
  infoBox: {
    backgroundColor:  '#1e293b',
    padding: 18,
    borderRadius: 15,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: '#3b82f6',
  },
  infoTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 12,
    color: '#3b82f6',
  },
  infoText: {
    fontSize: 14,
    color: '#cbd5e1',
    lineHeight: 24,
  },
  logoutButton: {
    padding: 16,
    alignItems: 'center',
    backgroundColor: '#1e293b',
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#ef4444',
  },
  logoutText: {
    color: '#ef4444',
    fontSize: 16,
    fontWeight: '600',
  },
});