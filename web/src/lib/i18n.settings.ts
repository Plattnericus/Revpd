/*
  Names for the individual settings.

  Separate from the main dictionary because these follow the configuration
  file: a setting added to the registry on the server appears here, and one
  removed disappears. Keeping them apart means the main dictionary stays a
  fixed set that the completeness check can be strict about, while this one
  grows with the product.

  The lookup falls back to English and then to the key itself, so a setting
  added on the server before its name is translated shows something readable
  rather than an empty label.
*/

import type { Lang } from './i18n'

type Labels = Record<string, string>

const en: Labels = {
  // Network
  'web.listen': 'Web interface',
  'web.listen_fallbacks': 'Alternative ports',
  'web.http_listen': 'Plain HTTP',
  'web.http_listen_fallbacks': 'Alternative HTTP ports',
  'web.hostname': 'Hostname',
  'relay.listen': 'Remote Desktop',

  // Access
  'grant.ttl': 'Access valid for',
  'grant.reuse_window': 'Reconnect window',
  'grant.ipv4_prefix_bits': 'IPv4 match',
  'grant.ipv6_prefix_bits': 'IPv6 match',

  // Sign-in
  'auth.session_ttl': 'Session length',
  'auth.session_idle': 'Idle timeout',
  'auth.max_failures': 'Failed attempts',
  'auth.lockout_base': 'First lockout',
  'auth.lockout_max': 'Longest lockout',
  'auth.totp_skew': 'Clock tolerance',
  'auth.backup_codes': 'Backup codes',

  // Relay
  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Connections per address',
  'relay.dial_timeout': 'Connect timeout',
  'relay.idle_timeout': 'Session idle timeout',

  // Remote desktop
  'rdp_login.enabled': 'Sign in from Remote Desktop',
  'rdp_login.pass_through_credentials': 'Pass the password on',
  'rdp_login.timeout': 'Sign-in timeout',
  'rdp_login.step_timeout': 'Step timeout',
  'jit.enabled': 'Push approval',
  'jit.hold_timeout': 'Approval wait',

  // Wake
  'wol.probe_interval': 'Check every',
  'wol.probe_settle': 'Settle time',
  'wol.repeat': 'Magic packets',

  // Updates
  'update.enabled': 'Check for updates',
  'update.auto_install': 'Install automatically',
  'update.only_when_idle': 'Only when nobody is connected',
  'update.prerelease': 'Accept pre-releases',
  'update.check_interval': 'Check every',
  'update.repo': 'Update source',
}

const de: Labels = {
  'web.listen': 'Weboberfläche',
  'web.listen_fallbacks': 'Ausweichports',
  'web.http_listen': 'Unverschlüsseltes HTTP',
  'web.http_listen_fallbacks': 'Ausweichports für HTTP',
  'web.hostname': 'Hostname',
  'relay.listen': 'Remotedesktop',

  'grant.ttl': 'Freigabe gültig für',
  'grant.reuse_window': 'Reconnect-Fenster',
  'grant.ipv4_prefix_bits': 'IPv4-Übereinstimmung',
  'grant.ipv6_prefix_bits': 'IPv6-Übereinstimmung',

  'auth.session_ttl': 'Sitzungsdauer',
  'auth.session_idle': 'Leerlauf-Abmeldung',
  'auth.max_failures': 'Fehlversuche',
  'auth.lockout_base': 'Erste Sperre',
  'auth.lockout_max': 'Längste Sperre',
  'auth.totp_skew': 'Uhrzeit-Toleranz',
  'auth.backup_codes': 'Backup-Codes',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Verbindungen je Adresse',
  'relay.dial_timeout': 'Verbindungs-Timeout',
  'relay.idle_timeout': 'Sitzungs-Leerlauf',

  'rdp_login.enabled': 'Anmeldung per Remotedesktop',
  'rdp_login.pass_through_credentials': 'Passwort weiterreichen',
  'rdp_login.timeout': 'Anmelde-Timeout',
  'rdp_login.step_timeout': 'Schritt-Timeout',
  'jit.enabled': 'Push-Bestätigung',
  'jit.hold_timeout': 'Wartezeit auf Bestätigung',

  'wol.probe_interval': 'Prüfen alle',
  'wol.probe_settle': 'Nachlaufzeit',
  'wol.repeat': 'Magic Packets',

  'update.enabled': 'Nach Updates suchen',
  'update.auto_install': 'Automatisch installieren',
  'update.only_when_idle': 'Nur wenn niemand verbunden ist',
  'update.prerelease': 'Vorabversionen akzeptieren',
  'update.check_interval': 'Prüfen alle',
  'update.repo': 'Update-Quelle',
}

const fr: Labels = {
  'web.listen': 'Interface web',
  'web.listen_fallbacks': 'Ports de secours',
  'web.http_listen': 'HTTP non chiffré',
  'web.http_listen_fallbacks': 'Ports HTTP de secours',
  'web.hostname': 'Nom d’hôte',
  'relay.listen': 'Bureau à distance',

  'grant.ttl': 'Accès valable',
  'grant.reuse_window': 'Fenêtre de reconnexion',
  'grant.ipv4_prefix_bits': 'Correspondance IPv4',
  'grant.ipv6_prefix_bits': 'Correspondance IPv6',

  'auth.session_ttl': 'Durée de session',
  'auth.session_idle': 'Expiration par inactivité',
  'auth.max_failures': 'Tentatives échouées',
  'auth.lockout_base': 'Premier blocage',
  'auth.lockout_max': 'Blocage maximal',
  'auth.totp_skew': 'Tolérance d’horloge',
  'auth.backup_codes': 'Codes de secours',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Connexions par adresse',
  'relay.dial_timeout': 'Délai de connexion',
  'relay.idle_timeout': 'Inactivité de session',

  'rdp_login.enabled': 'Connexion depuis Bureau à distance',
  'rdp_login.pass_through_credentials': 'Transmettre le mot de passe',
  'rdp_login.timeout': 'Délai de connexion',
  'rdp_login.step_timeout': 'Délai par étape',
  'jit.enabled': 'Validation par notification',
  'jit.hold_timeout': 'Attente de validation',

  'wol.probe_interval': 'Vérifier toutes les',
  'wol.probe_settle': 'Temps de stabilisation',
  'wol.repeat': 'Paquets magiques',

  'update.enabled': 'Rechercher des mises à jour',
  'update.auto_install': 'Installer automatiquement',
  'update.only_when_idle': 'Seulement si personne n’est connecté',
  'update.prerelease': 'Accepter les préversions',
  'update.check_interval': 'Vérifier toutes les',
  'update.repo': 'Source des mises à jour',
}

const es: Labels = {
  'web.listen': 'Interfaz web',
  'web.listen_fallbacks': 'Puertos alternativos',
  'web.http_listen': 'HTTP sin cifrar',
  'web.http_listen_fallbacks': 'Puertos HTTP alternativos',
  'web.hostname': 'Nombre de host',
  'relay.listen': 'Escritorio remoto',

  'grant.ttl': 'Acceso válido durante',
  'grant.reuse_window': 'Ventana de reconexión',
  'grant.ipv4_prefix_bits': 'Coincidencia IPv4',
  'grant.ipv6_prefix_bits': 'Coincidencia IPv6',

  'auth.session_ttl': 'Duración de sesión',
  'auth.session_idle': 'Cierre por inactividad',
  'auth.max_failures': 'Intentos fallidos',
  'auth.lockout_base': 'Primer bloqueo',
  'auth.lockout_max': 'Bloqueo máximo',
  'auth.totp_skew': 'Tolerancia de reloj',
  'auth.backup_codes': 'Códigos de respaldo',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Conexiones por dirección',
  'relay.dial_timeout': 'Tiempo de conexión',
  'relay.idle_timeout': 'Inactividad de sesión',

  'rdp_login.enabled': 'Iniciar sesión desde Escritorio remoto',
  'rdp_login.pass_through_credentials': 'Pasar la contraseña',
  'rdp_login.timeout': 'Tiempo de inicio de sesión',
  'rdp_login.step_timeout': 'Tiempo por paso',
  'jit.enabled': 'Aprobación push',
  'jit.hold_timeout': 'Espera de aprobación',

  'wol.probe_interval': 'Comprobar cada',
  'wol.probe_settle': 'Tiempo de estabilización',
  'wol.repeat': 'Paquetes mágicos',

  'update.enabled': 'Buscar actualizaciones',
  'update.auto_install': 'Instalar automáticamente',
  'update.only_when_idle': 'Solo si no hay nadie conectado',
  'update.prerelease': 'Aceptar versiones preliminares',
  'update.check_interval': 'Comprobar cada',
  'update.repo': 'Origen de actualizaciones',
}

const it: Labels = {
  'web.listen': 'Interfaccia web',
  'web.listen_fallbacks': 'Porte alternative',
  'web.http_listen': 'HTTP in chiaro',
  'web.http_listen_fallbacks': 'Porte HTTP alternative',
  'web.hostname': 'Nome host',
  'relay.listen': 'Desktop remoto',

  'grant.ttl': 'Accesso valido per',
  'grant.reuse_window': 'Finestra di riconnessione',
  'grant.ipv4_prefix_bits': 'Corrispondenza IPv4',
  'grant.ipv6_prefix_bits': 'Corrispondenza IPv6',

  'auth.session_ttl': 'Durata sessione',
  'auth.session_idle': 'Scadenza per inattività',
  'auth.max_failures': 'Tentativi falliti',
  'auth.lockout_base': 'Primo blocco',
  'auth.lockout_max': 'Blocco massimo',
  'auth.totp_skew': 'Tolleranza orologio',
  'auth.backup_codes': 'Codici di riserva',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Connessioni per indirizzo',
  'relay.dial_timeout': 'Timeout di connessione',
  'relay.idle_timeout': 'Inattività sessione',

  'rdp_login.enabled': 'Accesso da Desktop remoto',
  'rdp_login.pass_through_credentials': 'Inoltra la password',
  'rdp_login.timeout': 'Timeout di accesso',
  'rdp_login.step_timeout': 'Timeout per passaggio',
  'jit.enabled': 'Approvazione push',
  'jit.hold_timeout': 'Attesa approvazione',

  'wol.probe_interval': 'Controlla ogni',
  'wol.probe_settle': 'Tempo di assestamento',
  'wol.repeat': 'Pacchetti magici',

  'update.enabled': 'Cerca aggiornamenti',
  'update.auto_install': 'Installa automaticamente',
  'update.only_when_idle': 'Solo se non è connesso nessuno',
  'update.prerelease': 'Accetta versioni preliminari',
  'update.check_interval': 'Controlla ogni',
  'update.repo': 'Origine aggiornamenti',
}

const nl: Labels = {
  'web.listen': 'Webinterface',
  'web.listen_fallbacks': 'Uitwijkpoorten',
  'web.http_listen': 'Onversleuteld HTTP',
  'web.http_listen_fallbacks': 'Uitwijkpoorten voor HTTP',
  'web.hostname': 'Hostnaam',
  'relay.listen': 'Extern bureaublad',

  'grant.ttl': 'Toegang geldig voor',
  'grant.reuse_window': 'Herverbindingsvenster',
  'grant.ipv4_prefix_bits': 'IPv4-overeenkomst',
  'grant.ipv6_prefix_bits': 'IPv6-overeenkomst',

  'auth.session_ttl': 'Sessieduur',
  'auth.session_idle': 'Afmelden bij inactiviteit',
  'auth.max_failures': 'Mislukte pogingen',
  'auth.lockout_base': 'Eerste blokkade',
  'auth.lockout_max': 'Langste blokkade',
  'auth.totp_skew': 'Kloktolerantie',
  'auth.backup_codes': 'Back-upcodes',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Verbindingen per adres',
  'relay.dial_timeout': 'Verbindingstime-out',
  'relay.idle_timeout': 'Sessie-inactiviteit',

  'rdp_login.enabled': 'Aanmelden vanuit Extern bureaublad',
  'rdp_login.pass_through_credentials': 'Wachtwoord doorgeven',
  'rdp_login.timeout': 'Aanmeldtime-out',
  'rdp_login.step_timeout': 'Time-out per stap',
  'jit.enabled': 'Push-goedkeuring',
  'jit.hold_timeout': 'Wachten op goedkeuring',

  'wol.probe_interval': 'Controleer elke',
  'wol.probe_settle': 'Stabilisatietijd',
  'wol.repeat': 'Magic packets',

  'update.enabled': 'Zoeken naar updates',
  'update.auto_install': 'Automatisch installeren',
  'update.only_when_idle': 'Alleen als er niemand verbonden is',
  'update.prerelease': 'Voorlopige versies accepteren',
  'update.check_interval': 'Controleer elke',
  'update.repo': 'Updatebron',
}

const pl: Labels = {
  'web.listen': 'Interfejs webowy',
  'web.listen_fallbacks': 'Porty zapasowe',
  'web.http_listen': 'Nieszyfrowany HTTP',
  'web.http_listen_fallbacks': 'Zapasowe porty HTTP',
  'web.hostname': 'Nazwa hosta',
  'relay.listen': 'Pulpit zdalny',

  'grant.ttl': 'Dostęp ważny przez',
  'grant.reuse_window': 'Okno ponownego połączenia',
  'grant.ipv4_prefix_bits': 'Dopasowanie IPv4',
  'grant.ipv6_prefix_bits': 'Dopasowanie IPv6',

  'auth.session_ttl': 'Czas trwania sesji',
  'auth.session_idle': 'Wylogowanie po bezczynności',
  'auth.max_failures': 'Nieudane próby',
  'auth.lockout_base': 'Pierwsza blokada',
  'auth.lockout_max': 'Najdłuższa blokada',
  'auth.totp_skew': 'Tolerancja zegara',
  'auth.backup_codes': 'Kody zapasowe',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Połączenia na adres',
  'relay.dial_timeout': 'Limit czasu połączenia',
  'relay.idle_timeout': 'Bezczynność sesji',

  'rdp_login.enabled': 'Logowanie z Pulpitu zdalnego',
  'rdp_login.pass_through_credentials': 'Przekaż hasło dalej',
  'rdp_login.timeout': 'Limit czasu logowania',
  'rdp_login.step_timeout': 'Limit czasu kroku',
  'jit.enabled': 'Zatwierdzanie push',
  'jit.hold_timeout': 'Oczekiwanie na zatwierdzenie',

  'wol.probe_interval': 'Sprawdzaj co',
  'wol.probe_settle': 'Czas ustabilizowania',
  'wol.repeat': 'Pakiety magiczne',

  'update.enabled': 'Sprawdzaj aktualizacje',
  'update.auto_install': 'Instaluj automatycznie',
  'update.only_when_idle': 'Tylko gdy nikt nie jest połączony',
  'update.prerelease': 'Akceptuj wersje wstępne',
  'update.check_interval': 'Sprawdzaj co',
  'update.repo': 'Źródło aktualizacji',
}

const pt: Labels = {
  'web.listen': 'Interface web',
  'web.listen_fallbacks': 'Portas alternativas',
  'web.http_listen': 'HTTP sem cifra',
  'web.http_listen_fallbacks': 'Portas HTTP alternativas',
  'web.hostname': 'Nome do anfitrião',
  'relay.listen': 'Ambiente de trabalho remoto',

  'grant.ttl': 'Acesso válido por',
  'grant.reuse_window': 'Janela de reconexão',
  'grant.ipv4_prefix_bits': 'Correspondência IPv4',
  'grant.ipv6_prefix_bits': 'Correspondência IPv6',

  'auth.session_ttl': 'Duração da sessão',
  'auth.session_idle': 'Terminar por inatividade',
  'auth.max_failures': 'Tentativas falhadas',
  'auth.lockout_base': 'Primeiro bloqueio',
  'auth.lockout_max': 'Bloqueio máximo',
  'auth.totp_skew': 'Tolerância do relógio',
  'auth.backup_codes': 'Códigos de recuperação',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Ligações por endereço',
  'relay.dial_timeout': 'Tempo limite de ligação',
  'relay.idle_timeout': 'Inatividade da sessão',

  'rdp_login.enabled': 'Iniciar sessão a partir do ambiente remoto',
  'rdp_login.pass_through_credentials': 'Encaminhar a palavra-passe',
  'rdp_login.timeout': 'Tempo limite de início de sessão',
  'rdp_login.step_timeout': 'Tempo limite por passo',
  'jit.enabled': 'Aprovação por push',
  'jit.hold_timeout': 'Espera pela aprovação',

  'wol.probe_interval': 'Verificar a cada',
  'wol.probe_settle': 'Tempo de estabilização',
  'wol.repeat': 'Pacotes mágicos',

  'update.enabled': 'Procurar atualizações',
  'update.auto_install': 'Instalar automaticamente',
  'update.only_when_idle': 'Apenas quando ninguém está ligado',
  'update.prerelease': 'Aceitar versões preliminares',
  'update.check_interval': 'Verificar a cada',
  'update.repo': 'Origem das atualizações',
}

const tr: Labels = {
  'web.listen': 'Web arayüzü',
  'web.listen_fallbacks': 'Yedek bağlantı noktaları',
  'web.http_listen': 'Şifresiz HTTP',
  'web.http_listen_fallbacks': 'Yedek HTTP bağlantı noktaları',
  'web.hostname': 'Ana makine adı',
  'relay.listen': 'Uzak Masaüstü',

  'grant.ttl': 'Erişim geçerlilik süresi',
  'grant.reuse_window': 'Yeniden bağlanma penceresi',
  'grant.ipv4_prefix_bits': 'IPv4 eşleşmesi',
  'grant.ipv6_prefix_bits': 'IPv6 eşleşmesi',

  'auth.session_ttl': 'Oturum süresi',
  'auth.session_idle': 'Boşta kalma süresi',
  'auth.max_failures': 'Başarısız denemeler',
  'auth.lockout_base': 'İlk kilitlenme',
  'auth.lockout_max': 'En uzun kilitlenme',
  'auth.totp_skew': 'Saat toleransı',
  'auth.backup_codes': 'Yedek kodlar',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Adres başına bağlantı',
  'relay.dial_timeout': 'Bağlanma zaman aşımı',
  'relay.idle_timeout': 'Oturum boşta kalma',

  'rdp_login.enabled': 'Uzak Masaüstü’nden oturum açma',
  'rdp_login.pass_through_credentials': 'Parolayı ilet',
  'rdp_login.timeout': 'Oturum açma zaman aşımı',
  'rdp_login.step_timeout': 'Adım zaman aşımı',
  'jit.enabled': 'Anlık onay',
  'jit.hold_timeout': 'Onay bekleme',

  'wol.probe_interval': 'Kontrol aralığı',
  'wol.probe_settle': 'Yerleşme süresi',
  'wol.repeat': 'Sihirli paketler',

  'update.enabled': 'Güncellemeleri ara',
  'update.auto_install': 'Otomatik kur',
  'update.only_when_idle': 'Yalnızca kimse bağlı değilken',
  'update.prerelease': 'Ön sürümleri kabul et',
  'update.check_interval': 'Kontrol aralığı',
  'update.repo': 'Güncelleme kaynağı',
}

const ru: Labels = {
  'web.listen': 'Веб-интерфейс',
  'web.listen_fallbacks': 'Запасные порты',
  'web.http_listen': 'Незашифрованный HTTP',
  'web.http_listen_fallbacks': 'Запасные порты HTTP',
  'web.hostname': 'Имя хоста',
  'relay.listen': 'Удалённый рабочий стол',

  'grant.ttl': 'Доступ действует',
  'grant.reuse_window': 'Окно переподключения',
  'grant.ipv4_prefix_bits': 'Совпадение IPv4',
  'grant.ipv6_prefix_bits': 'Совпадение IPv6',

  'auth.session_ttl': 'Длительность сеанса',
  'auth.session_idle': 'Выход по бездействию',
  'auth.max_failures': 'Неудачные попытки',
  'auth.lockout_base': 'Первая блокировка',
  'auth.lockout_max': 'Максимальная блокировка',
  'auth.totp_skew': 'Допуск часов',
  'auth.backup_codes': 'Резервные коды',

  'relay.tarpit': 'Tarpit',
  'relay.max_conns_per_ip': 'Подключений с адреса',
  'relay.dial_timeout': 'Тайм-аут подключения',
  'relay.idle_timeout': 'Бездействие сеанса',

  'rdp_login.enabled': 'Вход из «Удалённого рабочего стола»',
  'rdp_login.pass_through_credentials': 'Передавать пароль дальше',
  'rdp_login.timeout': 'Тайм-аут входа',
  'rdp_login.step_timeout': 'Тайм-аут шага',
  'jit.enabled': 'Подтверждение по push',
  'jit.hold_timeout': 'Ожидание подтверждения',

  'wol.probe_interval': 'Проверять каждые',
  'wol.probe_settle': 'Время стабилизации',
  'wol.repeat': 'Magic-пакеты',

  'update.enabled': 'Проверять обновления',
  'update.auto_install': 'Устанавливать автоматически',
  'update.only_when_idle': 'Только когда никто не подключён',
  'update.prerelease': 'Принимать предварительные версии',
  'update.check_interval': 'Проверять каждые',
  'update.repo': 'Источник обновлений',
}

const labels: Record<Lang, Labels> = { de, en, fr, es, it, nl, pl, pt, tr, ru }

/** Every key the settings page knows a name for. Used by the completeness check. */
export const settingKeys = Object.keys(en)

/**
 * settingLabel names one setting.
 *
 * A setting added on the server before it is named here falls back to English
 * and then to the key itself, so the page never shows an empty label.
 */
export function settingLabel(lang: Lang, key: string): string {
  return labels[lang]?.[key] ?? en[key] ?? key
}

export { labels as settingLabels }
