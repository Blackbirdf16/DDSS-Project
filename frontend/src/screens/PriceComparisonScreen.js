import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  ActivityIndicator,
  TouchableOpacity,
  Alert,
  TextInput,
} from 'react-native';
import { tripAPI } from '../services/api';

export default function PriceComparisonScreen({ navigation }) {
  const [loading, setLoading] = useState(false);
  const [prices, setPrices] = useState([]);
  const [origin, setOrigin] = useState('');
  const [destination, setDestination] = useState('');

  const handleComparePrices = async () => {
    if (!origin || ! destination) {
      Alert.alert('Error', 'Please enter both origin and destination');
      return;
    }

    setLoading(true);
    try {
      // Create trip request first
      const tripData = {
        origin,
        destination,
        passenger_count: 1,
      };

      const tripResult = await tripAPI.createTrip(tripData);
      const tripId = tripResult.trip_id;

      // Get price comparisons
      const priceResult = await tripAPI.getPrices(tripId);
      setPrices(priceResult.prices || []);
    } catch (error) {
      console.error('Price comparison error:', error);
      Alert.alert(
        'Error',
        error.response?.data?.detail || 'Could not fetch prices'
      );
    } finally {
      setLoading(false);
    }
  };

  const renderPriceItem = ({ item }) => (
    <View style={styles.priceCard}>
      <Text style={styles.providerName}>{item.provider}</Text>
      <Text style={styles.priceAmount}>${item.price. toFixed(2)}</Text>
      <Text style={styles. estimatedTime}>
        Est. Time: {item.estimated_time} min
      </Text>
      <TouchableOpacity style={styles.selectButton}>
        <Text style={styles. selectButtonText}>Select</Text>
      </TouchableOpacity>
    </View>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Text style={styles.backButton}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.title}>💰 Compare Prices</Text>
      </View>

      <View style={styles.formContainer}>
        <TextInput
          style={styles.input}
          placeholder="Origin (e.g., 123 Main St)"
          placeholderTextColor="#94a3b8"
          value={origin}
          onChangeText={setOrigin}
        />

        <TextInput
          style={styles.input}
          placeholder="Destination (e.g., 456 Park Ave)"
          placeholderTextColor="#94a3b8"
          value={destination}
          onChangeText={setDestination}
        />

        <TouchableOpacity
          style={[styles.compareButton, loading && styles.buttonDisabled]}
          onPress={handleComparePrices}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.compareButtonText}>Compare Prices</Text>
          )}
        </TouchableOpacity>
      </View>

      {prices.length > 0 && (
        <View style={styles.resultsContainer}>
          <Text style={styles.resultsTitle}>
            Found {prices.length} options
          </Text>
          <FlatList
            data={prices}
            renderItem={renderPriceItem}
            keyExtractor={(item, index) => index.toString()}
            contentContainerStyle={styles. listContainer}
          />
        </View>
      )}

      {! loading && prices.length === 0 && origin && destination && (
        <View style={styles.emptyState}>
          <Text style={styles.emptyText}>
            Enter origin and destination to compare prices
          </Text>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f172a',
  },
  header: {
    padding: 20,
    paddingTop: 40,
  },
  backButton: {
    color: '#f59e0b',
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 10,
  },
  title:  {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#ffffff',
    textAlign: 'center',
  },
  formContainer: {
    padding: 20,
    backgroundColor: '#1e293b',
    margin: 20,
    borderRadius: 16,
  },
  input: {
    backgroundColor: '#334155',
    color: '#ffffff',
    padding: 16,
    borderRadius: 12,
    marginBottom: 12,
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#475569',
  },
  compareButton: {
    backgroundColor: '#f59e0b',
    padding: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 8,
  },
  buttonDisabled: {
    backgroundColor: '#92400e',
    opacity: 0.6,
  },
  compareButtonText: {
    color:  '#ffffff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  resultsContainer: {
    flex: 1,
    padding:  20,
  },
  resultsTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#f59e0b',
    marginBottom:  16,
  },
  listContainer: {
    paddingBottom: 20,
  },
  priceCard: {
    backgroundColor:  '#1e293b',
    padding: 20,
    borderRadius: 12,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#334155',
  },
  providerName: {
    fontSize:  20,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 8,
  },
  priceAmount: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#f59e0b',
    marginBottom: 8,
  },
  estimatedTime: {
    fontSize: 14,
    color: '#cbd5e1',
    marginBottom: 12,
  },
  selectButton: {
    backgroundColor: '#10b981',
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  selectButtonText: {
    color: '#ffffff',
    fontWeight: 'bold',
    fontSize: 16,
  },
  emptyState: {
    flex:  1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 40,
  },
  emptyText: {
    color: '#94a3b8',
    fontSize: 16,
    textAlign: 'center',
  },
});