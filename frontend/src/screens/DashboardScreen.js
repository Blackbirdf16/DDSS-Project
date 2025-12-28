import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
} from 'react-native';

export default function DashboardScreen({ navigation }) {
  const handleLogout = () => {
    // Navigate back to login
    navigation.replace('Login');
  };

  const handleCompareRides = () => {
    // Navigate to price comparison screen
    navigation.navigate('PriceComparison');
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles. content}>
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.appTitle}>🚕 FAIRRIDE</Text>
          <Text style={styles.welcomeText}>Dashboard</Text>
          <Text style={styles.subtitle}>Get a Fair Price, Every Time</Text>
        </View>

        {/* Main Content Cards */}
        <View style={styles.cardContainer}>
          {/* Compare Prices Card */}
          <TouchableOpacity
            style={styles.card}
            onPress={handleCompareRides}
          >
            <Text style={styles.cardIcon}>💰</Text>
            <Text style={styles.cardTitle}>Compare Prices</Text>
            <Text style={styles.cardDescription}>
              Find the best ride-sharing deals across multiple providers
            </Text>
          </TouchableOpacity>

          {/* Trip History Card */}
          <TouchableOpacity style={styles.card}>
            <Text style={styles. cardIcon}>📊</Text>
            <Text style={styles.cardTitle}>Trip History</Text>
            <Text style={styles.cardDescription}>
              View your previous rides and price comparisons
            </Text>
          </TouchableOpacity>

          {/* Saved Routes Card */}
          <TouchableOpacity style={styles.card}>
            <Text style={styles. cardIcon}>⭐</Text>
            <Text style={styles.cardTitle}>Saved Routes</Text>
            <Text style={styles.cardDescription}>
              Quick access to your frequently used routes
            </Text>
          </TouchableOpacity>

          {/* Settings Card */}
          <TouchableOpacity style={styles.card}>
            <Text style={styles.cardIcon}>⚙️</Text>
            <Text style={styles.cardTitle}>Settings</Text>
            <Text style={styles.cardDescription}>
              Manage your account and preferences
            </Text>
          </TouchableOpacity>
        </View>

        {/* Quick Stats */}
        <View style={styles.statsContainer}>
          <Text style={styles.statsTitle}>Your Stats</Text>
          <View style={styles.statsGrid}>
            <View style={styles.statItem}>
              <Text style={styles.statValue}>12</Text>
              <Text style={styles.statLabel}>Total Trips</Text>
            </View>
            <View style={styles. statItem}>
              <Text style={styles.statValue}>$127</Text>
              <Text style={styles.statLabel}>Money Saved</Text>
            </View>
            <View style={styles.statItem}>
              <Text style={styles.statValue}>8</Text>
              <Text style={styles.statLabel}>This Month</Text>
            </View>
          </View>
        </View>

        {/* Logout Button */}
        <TouchableOpacity
          style={styles.logoutButton}
          onPress={handleLogout}
        >
          <Text style={styles.logoutButtonText}>🚪 Logout</Text>
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
    flex: 1,
    padding: 20,
    paddingTop: 40,
  },
  header:  {
    marginBottom: 30,
  },
  appTitle: {
    fontSize: 42,
    fontWeight: 'bold',
    textAlign: 'center',
    color: '#f59e0b',
    marginBottom: 8,
    letterSpacing: 2,
  },
  welcomeText: {
    fontSize: 28,
    fontWeight: 'bold',
    textAlign: 'center',
    color: '#ffffff',
    marginBottom: 4,
  },
  subtitle:  {
    fontSize: 16,
    textAlign: 'center',
    color: '#f59e0b',
    fontWeight: '600',
  },
  cardContainer: {
    marginBottom: 30,
  },
  card:  {
    backgroundColor: '#1e293b',
    padding:  20,
    borderRadius:  16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity:  0.3,
    shadowRadius: 8,
    elevation: 6,
    borderWidth: 1,
    borderColor: '#334155',
  },
  cardIcon: {
    fontSize: 36,
    marginBottom: 10,
    textAlign: 'center',
  },
  cardTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 8,
    textAlign: 'center',
  },
  cardDescription: {
    fontSize: 14,
    color: '#cbd5e1',
    textAlign: 'center',
    lineHeight: 20,
  },
  statsContainer: {
    backgroundColor: '#1e293b',
    padding: 20,
    borderRadius: 16,
    marginBottom: 24,
    borderWidth: 1,
    borderColor: '#f59e0b',
  },
  statsTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#f59e0b',
    marginBottom: 16,
    textAlign: 'center',
  },
  statsGrid: {
    flexDirection:  'row',
    justifyContent: 'space-around',
  },
  statItem: {
    alignItems: 'center',
  },
  statValue: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 4,
  },
  statLabel: {
    fontSize: 12,
    color: '#cbd5e1',
    textAlign:  'center',
  },
  logoutButton: {
    backgroundColor: '#dc2626',
    padding: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 10,
    shadowColor: '#dc2626',
    shadowOffset:  { width: 0, height:  4 },
    shadowOpacity:  0.3,
    shadowRadius: 8,
    elevation: 6,
  },
  logoutButtonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: 'bold',
  },
});