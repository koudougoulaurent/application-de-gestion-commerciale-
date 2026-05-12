#!/bin/bash
# ─────────────────────────────────────────────
#  GAFAROU — Démarrage du système de crédits
# ─────────────────────────────────────────────
cd "$(dirname "$0")"

echo "══════════════════════════════════════════════"
echo "   GAFAROU — Système de Gestion des Crédits"
echo "══════════════════════════════════════════════"
echo ""

# Vérifier Python
if ! command -v python3 &>/dev/null; then
  echo "❌ Python3 introuvable. Installez Python depuis https://python.org"
  exit 1
fi

# Créer un environnement virtuel si absent
if [ ! -d "venv" ]; then
  echo "⚙️  Création de l'environnement virtuel..."
  python3 -m venv venv
fi

# Activer l'environnement
source venv/bin/activate

# Installer les dépendances
echo "📦 Installation des dépendances..."
pip install -q -r requirements.txt

echo ""
echo "✅ Démarrage du serveur..."
echo "🌐 Ouvrez votre navigateur : http://127.0.0.1:5000"
echo "   (Appuyez sur Ctrl+C pour arrêter)"
echo ""

# Ouvrir le navigateur automatiquement après 1s
(sleep 1.5 && open "http://127.0.0.1:5000") &

python3 app.py
