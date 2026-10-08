import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiService {
  static const String baseUrl = 'http://127.0.0.1:8000';

  static Future<Map<String, dynamic>> scanUrl(
    String url, {
    bool force = false,
  }) async {
    final uri = Uri.parse('$baseUrl/scan-url?force=$force');

    final response = await http.post(
      uri,
      headers: {
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'url': url,
      }),
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }

    throw Exception(
      'Failed to scan URL. '
      'Status: ${response.statusCode}. '
      'Body: ${response.body}',
    );
  }

  static Future<List<dynamic>> getScans() async {
    final uri = Uri.parse('$baseUrl/scan-history');

    final response = await http.get(
      uri,
      headers: {
        'Content-Type': 'application/json',
      },
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as List<dynamic>;
    }

    throw Exception(
      'Failed to load scan history. '
      'Status: ${response.statusCode}. '
      'Body: ${response.body}',
    );
  }

  static Future<Map<String, dynamic>> getDashboardSummary() async {
    final uri = Uri.parse('$baseUrl/dashboard-summary');

    final response = await http.get(
      uri,
      headers: {
        'Content-Type': 'application/json',
      },
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }

    throw Exception(
      'Failed to load dashboard summary. '
      'Status: ${response.statusCode}. '
      'Body: ${response.body}',
    );
  }
}