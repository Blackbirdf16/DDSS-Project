import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  Alert,
  Image,
} from 'react-native';

export default function DashboardScreen({ navigation }) {
  const [pickup, setPickup] = useState('');
  const [destination, setDestination] = useState('');

  const handleComparePrices = () => {
    if (! pickup || !destination) {
      Alert.alert('Error', 'Please enter both pickup and destination locations');
      return;
    }

    navigation.navigate('PriceComparison', {
      pickup,
      destination,
    });
  };

  const handleTripHistory = () => {
    Alert.alert(
      'Trip History',
      'No previous trips yet. Start comparing prices to build your history!'
    );
  };

  const handleSavedRoutes = () => {
    Alert.alert(
      'Saved Routes',
      'No saved routes yet. Complete trips to save your favorite routes!'
    );
  };

  return (
    <ScrollView style={styles.container}>
      {/* Header with YOUR Logo */}
      <View style={styles.header}>
        <Image
          source={require('../../assets/images/logo.png')}
          style={styles.logo}
          resizeMode="contain"
        />
        <View style={styles.titleContainer}>
          <Text style={styles.titleFair}>FAIR</Text>
          <Text style={styles.titleRide}>RIDE</Text>
        </View>
        <Text style={styles.subtitle}>Get a Fair Price, Every Time</Text>
        <View style={styles.regionBadge}>
          <Text style={styles.regionText}>🇪🇸 Spain • €</Text>
        </View>
      </View>

      {/* Main Content */}
      <View style={styles.content}>
        {/* Compare Prices Section - NO MONEY BAG! */}
        <View style={styles.card}>
          <View style={styles.cardHeader}>
            <View style={styles.iconContainer}>
              <Text style={styles.cardIcon}>📍</Text>
            </View>
            <Text style={styles. cardTitle}>Compare Prices</Text>
          </View>
          
          <Text style={styles.cardDescription}>
            Find the best ride-sharing deals across multiple providers
          </Text>

          <TextInput
            style={styles.input}
            placeholder="Pickup Location (e.g., Puerta del Sol, Madrid)"
            placeholderTextColor="#94a3b8"
            value={pickup}
            onChangeText={setPickup}
          />

          <TextInput
            style={styles.input}
            placeholder="Destination (e.g., Madrid-Barajas Airport)"
            placeholderTextColor="#94a3b8"
            value={destination}
            onChangeText={setDestination}
          />

          <TouchableOpacity
            style={styles.compareButton}
            onPress={handleComparePrices}
          >
            <Text style={styles.compareButtonText}>Compare Prices</Text>
          </TouchableOpacity>

          {/* Available Providers */}
          <View style={styles.pricePreview}>
            <Text style={styles.pricePreviewLabel}>Available providers in Spain:</Text>
            <View style={styles.providerTags}>
              <View style={[styles.providerTag, { backgroundColor: '#000000' }]}>
                <Text style={styles.providerTagText}>Uber</Text>
              </View>
              <View style={[styles.providerTag, { backgroundColor: '#6C1C99' }]}>
                <Text style={styles.providerTagText}>Cabify</Text>
              </View>
              <View style={[styles.providerTag, { backgroundColor: '#FFC933' }]}>
                <Text style={[styles.providerTagText, { color: '#000' }]}>FREE NOW</Text>
              </View>
              <View style={[styles.providerTag, { backgroundColor: '#34D186' }]}>
                <Text style={[styles.providerTagText, { color: '#000' }]}>Bolt</Text>
              </View>
            </View>
          </View>
        </View>

        {/* Trip History Section */}
        <TouchableOpacity
          style={styles.card}
          onPress={handleTripHistory}
          activeOpacity={0.7}
        >
          <View style={styles.cardHeader}>
            <View style={styles.iconContainer}>
              <Text style={styles.cardIcon}>🕒</Text>
            </View>
            <Text style={styles. cardTitle}>Trip History</Text>
          </View>
          <Text style={styles.cardDescription}>
            View your previous rides and price comparisons
          </Text>
          <View style={styles.emptyState}>
            <Text style={styles.emptyStateText}>No trips yet</Text>
            <Text style={styles.emptyStateSubtext}>
              Start comparing prices to see your history
            </Text>
          </View>
        </TouchableOpacity>

        {/* Saved Routes Section */}
        <TouchableOpacity
          style={styles.card}
          onPress={handleSavedRoutes}
          activeOpacity={0.7}
        >
          <View style={styles.cardHeader}>
            <View style={styles.iconContainer}>
              <Text style={styles.cardIcon}>⭐</Text>
            </View>
            <Text style={styles.cardTitle}>Saved Routes</Text>
          </View>
          <Text style={styles. cardDescription}>
            Quick access to your frequently used routes
          </Text>
          <View style={styles.emptyState}>
            <Text style={styles.emptyStateText}>No saved routes</Text>
            <Text style={styles.emptyStateSubtext}>
              Save routes for quick access later
            </Text>
          </View>
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
  header: {
    alignItems: 'center',
    paddingTop: 40,
    paddingBottom: 30,
    backgroundColor: '#1e293b',
    borderBottomLeftRadius: 30,
    borderBottomRightRadius: 30,
  },
  logo: {
    width: 80,
    height: 80,
    marginBottom: 15,
  },
  titleContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 10,
  },
  titleFair: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#f59e0b',
    letterSpacing: 2,
  },
  titleRide: {
    fontSize:  36,
    fontWeight:  'bold',
    color:  '#ffffff',
    letterSpacing: 2,
  },
  subtitle: {
    fontSize: 16,
    color: '#cbd5e1',
    fontWeight: '500',
    marginBottom: 12,
  },
  regionBadge: {
    backgroundColor: '#334155',
    paddingHorizontal: 16,
    paddingVertical:  8,
    borderRadius:  20,
  },
  regionText: {
    color: '#f59e0b',
    fontSize: 14,
    fontWeight: '600',
  },
  content: {
    padding: 20,
  },
  card:  {
    backgroundColor: '#1e293b',
    borderRadius: 20,
    padding: 24,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: '#334155',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity:  0.3,
    shadowRadius: 8,
    elevation: 6,
  },
  cardHeader:  {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom:  12,
  },
  iconContainer: {
    width: 40,
    height: 40,
    borderRadius: 12,
    backgroundColor: '#334155',
    justifyContent:  'center',
    alignItems: 'center',
    marginRight: 12,
  },
  cardIcon: {
    fontSize: 20,
  },
  cardTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  cardDescription: {
    fontSize: 14,
    color: '#94a3b8',
    marginBottom: 20,
    lineHeight: 20,
  },
  input: {
    backgroundColor: '#334155',
    color: '#ffffff',
    padding:  16,
    borderRadius:  12,
    marginBottom: 16,
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
    shadowColor: '#f59e0b',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity:  0.3,
    shadowRadius: 8,
    elevation: 6,
  },
  compareButtonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  pricePreview: {
    marginTop: 20,
    paddingTop: 20,
    borderTopWidth: 1,
    borderTopColor: '#334155',
  },
  pricePreviewLabel: {
    fontSize:  14,
    color: '#cbd5e1',
    marginBottom: 12,
    fontWeight: '600',
  },
  providerTags:  {
    flexDirection: 'row',
    flexWrap:  'wrap',
    gap: 8,
  },
  providerTag: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 8,
  },
  providerTagText:  {
    color: '#ffffff',
    fontSize: 12,
    fontWeight: '600',
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: 20,
  },
  emptyStateText:  {
    fontSize: 16,
    color:  '#cbd5e1',
    fontWeight: '600',
    marginBottom: 6,
  },
  emptyStateSubtext: {
    fontSize: 14,
    color: '#64748b',
    textAlign: 'center',
  },
});