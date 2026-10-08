import 'package:flutter/material.dart';

import 'services/api_service.dart';



void main() {

  runApp(const PhishingApp());

}



class PhishingApp extends StatelessWidget {

  const PhishingApp({super.key});



  @override

  Widget build(BuildContext context) {

    return MaterialApp(

      title: 'Lim phishing detector',

      debugShowCheckedModeBanner: false,

      theme: ThemeData(

        useMaterial3: true,

        fontFamily: 'Arial',

        scaffoldBackgroundColor: const Color(0xFF0F172A),

      ),

      home: const ScanPage(),

    );

  }

}



class ScanPage extends StatefulWidget {

  const ScanPage({super.key});



  @override

  State<ScanPage> createState() => _ScanPageState();

}



class _ScanPageState extends State<ScanPage> {

  final TextEditingController urlController = TextEditingController();



  bool loading = false;

  bool rescanning = false;

  Map<String, dynamic>? result;



  static const Color bgColor = Color(0xFF0F172A);

  static const Color panelColor = Color(0xFF111827);

  static const Color cardColor = Color(0xFF1E293B);

  static const Color inputColor = Color(0xFF334155);

  static const Color accentBlue = Color(0xFF3B82F6);

  static const Color successGreen = Color(0xFF10B981);

  static const Color warningOrange = Color(0xFFF59E0B);

  static const Color dangerRed = Color(0xFFEF4444);

  static const Color textWhite = Color(0xFFF8FAFC);

  static const Color mutedText = Color(0xFFCBD5E1);



  @override

  void dispose() {

    urlController.dispose();

    super.dispose();

  }



  // Accept only an actual scan result, including known wrapper shapes.
  Map<String, dynamic> _extractScanResult(Map<String, dynamic> response) {
    bool isScanResult(Map<String, dynamic> item) =>
        item.containsKey('verdict') ||
        item.containsKey('result') ||
        item.containsKey('risk_level') ||
        item.containsKey('reasons');

    if (isScanResult(response)) return response;

    for (final key in ['data', 'scan_result', 'scan', 'analysis']) {
      final inner = response[key];
      if (inner is Map) {
        final map = Map<String, dynamic>.from(inner);
        if (isScanResult(map)) return map;
      }
    }

    throw FormatException(
      'The server returned no scan verdict or risk details. '
      'Response keys: ${response.keys.join(', ')}',
    );
  }

  Future<void> scan({bool force = false}) async {
    final url = urlController.text.trim();
    if (url.isEmpty) {
      setState(() => result = {'error': 'Please enter a URL first.'});
      return;
    }
    if (loading || rescanning) return;

    setState(() {
      if (force) {
        rescanning = true;
      } else {
        loading = true;
        result = null;
      }
    });

    try {
      final data = await ApiService.scanUrl(url, force: force);
      debugPrint('RAW SCAN RESPONSE: $data');
      final parsed = _extractScanResult(data);
      if (!mounted) return;
      setState(() => result = parsed);
    } catch (e) {
      debugPrint('SCAN ERROR: $e');
      if (!mounted) return;
      setState(() => result = {'error': 'Scan failed: $e'});
    } finally {
      if (mounted) {
        setState(() {
          loading = false;
          rescanning = false;
        });
      }
    }
  }

  List<String> getReasons(dynamic reasonsData) {

    if (reasonsData == null) return [];



    if (reasonsData is List) {

      return reasonsData.map((item) => item.toString()).toList();

    }



    if (reasonsData is String) {

      return reasonsData

          .replaceAll("[", "")

          .replaceAll("]", "")

          .replaceAll("'", "")

          .split(",")

          .map((item) => item.trim())

          .where((item) => item.isNotEmpty)

          .toList();

    }



    return [reasonsData.toString()];

  }



  Color getAccentColor(String verdict) {

    switch (verdict) {

      case 'Safe':

        return successGreen;

      case 'Suspicious':

        return warningOrange;

      case 'Phishing':

      case 'High Risk':

        return dangerRed;

      default:

        return accentBlue;

    }

  }



  IconData getVerdictIcon(String verdict) {

    switch (verdict) {

      case 'Safe':

        return Icons.verified_outlined;

      case 'Suspicious':

        return Icons.report_problem_outlined;

      case 'Phishing':

      case 'High Risk':

        return Icons.dangerous_outlined;

      default:

        return Icons.help_outline;

    }

  }



  @override

  Widget build(BuildContext context) {

    final bool hasError = result?["error"] != null;

    final bool hasPreviousScan = result?["exists"] == true && !hasError;



    final String verdict =

        result?["verdict"]?.toString() ?? result?["result"]?.toString() ?? "";



    final List<String> reasons = getReasons(result?["reasons"]);

    final Color accentColor = hasError ? dangerRed : getAccentColor(verdict);



    final String resultTitle =

        hasError ? "Scan Error" : verdict.isEmpty ? "Unknown Result" : verdict;



    return Scaffold(

      backgroundColor: bgColor,

      body: SafeArea(

        child: Center(

          child: Container(

            constraints: const BoxConstraints(maxWidth: 1180),

            padding: const EdgeInsets.all(18),

            child: Column(

              children: [

                _Header(),



                const SizedBox(height: 18),



                Expanded(

                  child: SingleChildScrollView(

                    child: Column(

                      children: [

                        _SearchPanel(

                          controller: urlController,

                          loading: loading,

                          onScan: () => scan(),

                        ),



                        const SizedBox(height: 20),



                        if (result != null)

                          LayoutBuilder(

                            builder: (context, constraints) {

                              final bool wide = constraints.maxWidth > 820;



                              if (!wide) {

                                return Column(

                                  children: [

                                    _ResultSection(

                                      title: "Returned Results",

                                      child: _ResultCard(

                                        hasError: hasError,

                                        error: result?["error"]?.toString(),

                                        title: resultTitle,

                                        icon: hasError

                                            ? Icons.error_outline

                                            : getVerdictIcon(verdict),

                                        accentColor: accentColor,

                                        riskLevel:

                                            result?["risk_level"] ?? "Unknown",

                                        riskScore: result?["risk_score"] ??

                                            result?["score"] ??

                                            0,

                                        reasons: reasons,

                                        advice: result?["advice"] ??

                                            "No advice provided",

                                        rescanning: rescanning,

                                        onRescan: () => scan(force: true),

                                      ),

                                    ),

                                    if (hasPreviousScan) ...[

                                      const SizedBox(height: 16),

                                      _ResultSection(

                                        title: "Previous Scan",

                                        child: _PreviousScanCard(

                                          lastScanned:

                                              result?["last_scanned_at"] ??

                                                  "Unknown",

                                          riskLevel:

                                              result?["risk_level"] ?? "Unknown",

                                          riskScore: result?["risk_score"] ??

                                              result?["score"] ??

                                              0,

                                        ),

                                      ),

                                    ],

                                  ],

                                );

                              }



                              return Row(

                                crossAxisAlignment: CrossAxisAlignment.start,

                                children: [

                                  Expanded(

                                    flex: hasPreviousScan ? 7 : 1,

                                    child: _ResultSection(

                                      title: "Returned Results",

                                      child: _ResultCard(

                                        hasError: hasError,

                                        error: result?["error"]?.toString(),

                                        title: resultTitle,

                                        icon: hasError

                                            ? Icons.error_outline

                                            : getVerdictIcon(verdict),

                                        accentColor: accentColor,

                                        riskLevel:

                                            result?["risk_level"] ?? "Unknown",

                                        riskScore: result?["risk_score"] ??

                                            result?["score"] ??

                                            0,

                                        reasons: reasons,

                                        advice: result?["advice"] ??

                                            "No advice provided",

                                        rescanning: rescanning,

                                        onRescan: () => scan(force: true),

                                      ),

                                    ),

                                  ),

                                  if (hasPreviousScan) ...[

                                    const SizedBox(width: 18),

                                    Expanded(

                                      flex: 3,

                                      child: _ResultSection(

                                        title: "Previous Scan",

                                        child: _PreviousScanCard(

                                          lastScanned:

                                              result?["last_scanned_at"] ??

                                                  "Unknown",

                                          riskLevel:

                                              result?["risk_level"] ?? "Unknown",

                                          riskScore: result?["risk_score"] ??

                                              result?["score"] ??

                                              0,

                                        ),

                                      ),

                                    ),

                                  ],

                                ],

                              );

                            },

                          ),



                        const SizedBox(height: 18),



                        const Text(

                          "Designed by Mutebi Richard & Asimire Unique  Class of 2023."

                          "© 2026 Limkokwing University",

                          textAlign: TextAlign.center,

                          style: TextStyle(

                            color: mutedText,

                            fontSize: 11,

                          ),

                        ),

                      ],

                    ),

                  ),

                ),

              ],

            ),

          ),

        ),

      ),

    );

  }

}



class _Header extends StatelessWidget {

  @override

  Widget build(BuildContext context) {

    return Container(

      height: 58,

      padding: const EdgeInsets.symmetric(horizontal: 18),

      decoration: BoxDecoration(

        color: _ScanPageState.panelColor,

        borderRadius: BorderRadius.circular(16),

        border: Border.all(color: Colors.white10),

      ),

      child: const Row(

        children: [

          //Icon(Icons.security_outlined, color: _ScanPageState.accentBlue),

         // SizedBox(width: 10),

          Text(

            "Limkokwing Phishing Detector.",

            style: TextStyle(

              color: _ScanPageState.textWhite,

              fontSize: 18,

              fontWeight: FontWeight.w700,

              letterSpacing: 0.2,

            ),

          ),

          Spacer(),

          Text(

            "URL Scanner",

            style: TextStyle(

              color: _ScanPageState.mutedText,

              fontSize: 12,

            ),

          ),

        ],

      ),

    );

  }

}



class _SearchPanel extends StatelessWidget {

  final TextEditingController controller;

  final bool loading;

  final VoidCallback onScan;



  const _SearchPanel({

    required this.controller,

    required this.loading,

    required this.onScan,

  });



  @override

  Widget build(BuildContext context) {

    return Container(

      padding: const EdgeInsets.all(18),

      decoration: BoxDecoration(

        color: _ScanPageState.cardColor,

        borderRadius: BorderRadius.circular(18),

        border: Border.all(color: Colors.white10),

      ),

      child: Column(

        crossAxisAlignment: CrossAxisAlignment.start,

        children: [

          const Text(

            "Check a suspicious link",

            style: TextStyle(

              color: _ScanPageState.textWhite,

              fontSize: 17,

              fontWeight: FontWeight.w700,

            ),

          ),

          const SizedBox(height: 6),

          const Text(

            "Enter a URL below to analyse its phishing risk.",

            style: TextStyle(

              color: _ScanPageState.mutedText,

              fontSize: 13,

            ),

          ),

          const SizedBox(height: 14),

          Row(

            children: [

              Expanded(

                child: TextField(

                  controller: controller,

                  style: const TextStyle(

                    color: _ScanPageState.textWhite,

                    fontSize: 14,

                  ),

                  decoration: InputDecoration(

                    hintText: "https://example.com/login",

                    hintStyle: const TextStyle(

                      color: Color(0xFF94A3B8),

                      fontSize: 14,

                    ),

                    prefixIcon: const Icon(

                      Icons.link,

                      size: 20,

                      color: _ScanPageState.mutedText,

                    ),

                    filled: true,

                    fillColor: _ScanPageState.inputColor,

                    contentPadding: const EdgeInsets.symmetric(

                      horizontal: 14,

                      vertical: 14,

                    ),

                    border: OutlineInputBorder(

                      borderRadius: BorderRadius.circular(14),

                      borderSide: BorderSide.none,

                    ),

                  ),

                ),

              ),

              const SizedBox(width: 12),

              SizedBox(

                height: 48,

                width: 120,

                child: ElevatedButton.icon(

                  onPressed: loading ? null : onScan,

                  icon: loading

                      ? const SizedBox(

                          width: 15,

                          height: 15,

                          child: CircularProgressIndicator(

                            strokeWidth: 2,

                            color: Colors.white,

                          ),

                        )

                      : const Icon(Icons.search, size: 18),

                  label: Text(

                    loading ? "Scanning" : "Scan",

                    style: const TextStyle(fontSize: 13),

                  ),

                  style: ElevatedButton.styleFrom(

                    backgroundColor: _ScanPageState.accentBlue,

                    foregroundColor: Colors.white,

                    elevation: 0,

                    shape: RoundedRectangleBorder(

                      borderRadius: BorderRadius.circular(14),

                    ),

                  ),

                ),

              ),

            ],

          ),

        ],

      ),

    );

  }

}



class _ResultSection extends StatelessWidget {

  final String title;

  final Widget child;



  const _ResultSection({

    required this.title,

    required this.child,

  });



  @override

  Widget build(BuildContext context) {

    return Column(

      crossAxisAlignment: CrossAxisAlignment.start,

      children: [

        Text(

          title.toUpperCase(),

          style: const TextStyle(

            color: _ScanPageState.mutedText,

            fontSize: 12,

            fontWeight: FontWeight.w700,

            letterSpacing: 1.1,

          ),

        ),

        const SizedBox(height: 10),

        child,

      ],

    );

  }

}



class _ResultCard extends StatelessWidget {

  final bool hasError;

  final String? error;

  final IconData icon;

  final String title;

  final Color accentColor;

  final dynamic riskLevel;

  final dynamic riskScore;

  final List<String> reasons;

  final dynamic advice;

  final bool rescanning;

  final VoidCallback onRescan;



  const _ResultCard({

    required this.hasError,

    required this.error,

    required this.icon,

    required this.title,

    required this.accentColor,

    required this.riskLevel,

    required this.riskScore,

    required this.reasons,

    required this.advice,

    required this.rescanning,

    required this.onRescan,

  });



  @override

  Widget build(BuildContext context) {

    return Container(

      width: double.infinity,

      padding: const EdgeInsets.all(18),

      decoration: BoxDecoration(

        color: _ScanPageState.cardColor,

        borderRadius: BorderRadius.circular(18),

        border: Border(

          left: BorderSide(color: accentColor, width: 5),

        ),

      ),

      child: hasError

          ? Row(

              children: [

                Icon(icon, color: accentColor),

                const SizedBox(width: 10),

                Expanded(

                  child: Text(

                    error ?? "Something went wrong.",

                    style: const TextStyle(

                      color: _ScanPageState.textWhite,

                      fontSize: 14,

                      fontWeight: FontWeight.w600,

                    ),

                  ),

                ),

              ],

            )

          : Column(

              crossAxisAlignment: CrossAxisAlignment.start,

              children: [

                Row(

                  children: [

                    Icon(icon, color: accentColor, size: 24),

                    const SizedBox(width: 10),

                    Expanded(

                      child: Text(

                        "Result: $title",

                        style: const TextStyle(

                          color: _ScanPageState.textWhite,

                          fontSize: 18,

                          fontWeight: FontWeight.w700,

                        ),

                      ),

                    ),

                  ],

                ),



                const SizedBox(height: 14),



                Wrap(

                  spacing: 10,

                  runSpacing: 10,

                  children: [

                    _InfoChip(

                      label: "Risk Level",

                      value: riskLevel.toString(),

                    ),

                    _InfoChip(

                      label: "Risk Score",

                      value: riskScore.toString(),

                    ),

                  ],

                ),



                const SizedBox(height: 16),



                const Text(

                  "Reasons",

                  style: TextStyle(

                    color: _ScanPageState.textWhite,

                    fontSize: 14,

                    fontWeight: FontWeight.w700,

                  ),

                ),



                const SizedBox(height: 8),



                if (reasons.isEmpty)

                  const Text(

                    "• No specific reason provided",

                    style: TextStyle(

                      color: _ScanPageState.mutedText,

                      fontSize: 13,

                    ),

                  )

                else

                  ...reasons.map(

                    (reason) => Padding(

                      padding: const EdgeInsets.only(bottom: 6),

                      child: Text(

                        "• $reason",

                        style: const TextStyle(

                          color: _ScanPageState.mutedText,

                          fontSize: 13,

                          height: 1.35,

                        ),

                      ),

                    ),

                  ),



                const SizedBox(height: 14),



                Container(

                  width: double.infinity,

                  padding: const EdgeInsets.all(12),

                  decoration: BoxDecoration(

                    color: _ScanPageState.inputColor,

                    borderRadius: BorderRadius.circular(12),

                  ),

                  child: Text(

                    "Advice: $advice",

                    style: const TextStyle(

                      color: _ScanPageState.textWhite,

                      fontSize: 13,

                      height: 1.45,

                    ),

                  ),

                ),



                const SizedBox(height: 14),



                SizedBox(

                  height: 42,

                  child: OutlinedButton.icon(

                    onPressed: rescanning ? null : onRescan,

                    icon: rescanning

                        ? const SizedBox(

                            width: 15,

                            height: 15,

                            child: CircularProgressIndicator(strokeWidth: 2),

                          )

                        : const Icon(Icons.refresh, size: 17),

                    label: Text(

                      rescanning ? "Scanning again..." : "Scan Again",

                      style: const TextStyle(fontSize: 13),

                    ),

                    style: OutlinedButton.styleFrom(

                      foregroundColor: _ScanPageState.textWhite,

                      side: const BorderSide(color: Colors.white24),

                      shape: RoundedRectangleBorder(

                        borderRadius: BorderRadius.circular(12),

                      ),

                    ),

                  ),

                ),

              ],

            ),

    );

  }

}



class _PreviousScanCard extends StatelessWidget {

  final dynamic lastScanned;

  final dynamic riskLevel;

  final dynamic riskScore;



  const _PreviousScanCard({

    required this.lastScanned,

    required this.riskLevel,

    required this.riskScore,

  });



  @override

  Widget build(BuildContext context) {

    return Container(

      width: double.infinity,

      padding: const EdgeInsets.all(18),

      decoration: BoxDecoration(

        color: _ScanPageState.cardColor,

        borderRadius: BorderRadius.circular(18),

        border: Border.all(color: Colors.white10),

      ),

      child: Column(

        crossAxisAlignment: CrossAxisAlignment.start,

        children: [

          const Row(

            children: [

              Icon(

                Icons.history,

                color: _ScanPageState.accentBlue,

                size: 22,

              ),

              SizedBox(width: 8),

              Text(

                "Previous scan found",

                style: TextStyle(

                  color: _ScanPageState.textWhite,

                  fontSize: 15,

                  fontWeight: FontWeight.w700,

                ),

              ),

            ],

          ),

          const SizedBox(height: 12),

          const Text(

            "This URL was already scanned before.",

            style: TextStyle(

              color: _ScanPageState.mutedText,

              fontSize: 13,

              height: 1.4,

            ),

          ),

          const SizedBox(height: 14),

          _MiniInfo(label: "Last scanned", value: lastScanned.toString()),

          _MiniInfo(label: "Risk level", value: riskLevel.toString()),

          _MiniInfo(label: "Risk score", value: riskScore.toString()),

        ],

      ),

    );

  }

}



class _InfoChip extends StatelessWidget {

  final String label;

  final String value;



  const _InfoChip({

    required this.label,

    required this.value,

  });



  @override

  Widget build(BuildContext context) {

    return Container(

      padding: const EdgeInsets.symmetric(

        horizontal: 12,

        vertical: 8,

      ),

      decoration: BoxDecoration(

        color: _ScanPageState.inputColor,

        borderRadius: BorderRadius.circular(999),

      ),

      child: Text(

        "$label: $value",

        style: const TextStyle(

          color: _ScanPageState.textWhite,

          fontSize: 12,

          fontWeight: FontWeight.w600,

        ),

      ),

    );

  }

}



class _MiniInfo extends StatelessWidget {

  final String label;

  final String value;



  const _MiniInfo({

    required this.label,

    required this.value,

  });



  @override

  Widget build(BuildContext context) {

    return Padding(

      padding: const EdgeInsets.only(bottom: 7),

      child: Row(

        children: [

          Expanded(

            child: Text(

              label,

              style: const TextStyle(

                color: _ScanPageState.mutedText,

                fontSize: 12,

              ),

            ),

          ),

          Text(

            value,

            style: const TextStyle(

              color: _ScanPageState.textWhite,

              fontSize: 12,

              fontWeight: FontWeight.w700,

            ),

          ),

        ],

      ),

    );

  }

}