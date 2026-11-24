// ignore: deprecated_member_use
import 'package:flutter/material.dart';

import '../state/browser_state.dart';

class SecurityPanel extends StatelessWidget {
  const SecurityPanel({super.key, required this.state});

  final BrowserState state;

  Widget _status(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 96,
            child: Text(label, style: const TextStyle(fontWeight: FontWeight.w600)),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final s = state.strings;
    return Drawer(
      width: 380,
      child: SafeArea(
        child: AnimatedBuilder(
          animation: state,
          builder: (context, _) => ListView(
            padding: const EdgeInsets.all(16),
            children: [
              Row(
                children: [
                  const Icon(Icons.shield, color: Colors.green),
                  const SizedBox(width: 8),
                  Text(
                    s.securityTitle,
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ],
              ),
              const Divider(),
              SwitchListTile(
                title: const Text('DNS Security'),
                subtitle: Text(s.dnsSecuritySub),
                value: state.dnsSecurity,
                onChanged: state.setDnsSecurity,
              ),
              SwitchListTile(
                title: Text(s.strictTitle),
                subtitle: Text(s.strictSub),
                value: state.strictDnssec,
                onChanged: state.dnsSecurity ? state.setStrictDnssec : null,
              ),
              SwitchListTile(
                title: Text(s.cfOptTitle),
                subtitle: Text(s.cfOptSub),
                value: state.ipOptimization,
                onChanged: state.setIpOptimization,
              ),
              const Divider(),
              _status(s.statusLabel, state.statusMessage),
              _status(s.proxyLabel, state.proxyInfo),
              _status(s.hostLabel, state.currentHost),
              _status(s.ipLabel, state.selectedIp),
              _status(s.latencyLabel, state.latency),
              _status(s.dnssecLabel, state.dnssec),
              _status(s.reasonLabel, state.dnssecReason),
              const Divider(),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: state.refreshCloudflareIps,
                      icon: const Icon(Icons.update),
                      label: Text(s.refreshIps),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Text(
                s.recentRequests,
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 6),
              ...state.events.map(
                (event) => Card(
                  child: Padding(
                    padding: const EdgeInsets.all(8),
                    child: Text(event, style: const TextStyle(fontSize: 12)),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
