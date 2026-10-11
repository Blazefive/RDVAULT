// ========================================
// I18N DU PROCESSUS PRINCIPAL - Boîtes de dialogue natives et messages d'erreur IPC
// ========================================
// src/ (et donc src/locales/*.json) n'est pas empaqueté (electron-builder : build/** et electron/**) :
// les textes affichés par le processus principal (appairage de l'extension, approbations CLI, clé d'hôte
// SSH, erreurs de chargement, erreurs IPC affichées en toast) sont traduits ici, dans les 12 langues de
// l'interface.
//
// Langue utilisée, par ordre de priorité :
// 1. langue courante de l'interface, communiquée par le renderer (IPC validé 'set-ui-language') ;
// 2. LANG de config.cfg (fournisseur par défaut, remplaçable pour les tests) ;
// 3. anglais.
// Une clé absente dans une langue retombe sur l'anglais. Le texte français est STRICTEMENT celui
// affiché avant la traduction (aucun changement pour les utilisateurs francophones).

const SUPPORTED_LANGS = ['ar', 'de', 'en', 'es', 'fr', 'it', 'ja', 'ko', 'pt', 'ru', 'tr', 'zh'];
const FALLBACK_LANG = 'en';

const MESSAGES = {
  // ----- Boutons communs (0 = approuver, 1 = refuser) -----
  'button.allow': {
    ar: 'السماح', de: 'Zulassen', en: 'Allow', es: 'Permitir', fr: 'Autoriser', it: 'Consenti',
    ja: '許可', ko: '허용', pt: 'Permitir', ru: 'Разрешить', tr: 'İzin ver', zh: '允许',
  },
  'button.deny': {
    ar: 'رفض', de: 'Ablehnen', en: 'Deny', es: 'Denegar', fr: 'Refuser', it: 'Rifiuta',
    ja: '拒否', ko: '거부', pt: 'Recusar', ru: 'Отклонить', tr: 'Reddet', zh: '拒绝',
  },
  'button.rememberContinue': {
    ar: 'التذكر والمتابعة', de: 'Speichern und fortfahren', en: 'Remember and continue', es: 'Recordar y continuar',
    fr: 'Mémoriser et continuer', it: 'Memorizza e continua', ja: '記憶して続行', ko: '기억하고 계속',
    pt: 'Memorizar e continuar', ru: 'Запомнить и продолжить', tr: 'Hatırla ve devam et', zh: '记住并继续',
  },

  // ----- Appairage de l'extension Chrome (main.js) -----
  'pairing.title': {
    ar: 'إقران إضافة Chrome', de: 'Kopplung der Chrome-Erweiterung', en: 'Chrome extension pairing',
    es: 'Vinculación de la extensión de Chrome', fr: 'Appairage extension Chrome', it: "Associazione dell'estensione Chrome",
    ja: 'Chrome 拡張機能のペアリング', ko: 'Chrome 확장 프로그램 페어링', pt: 'Pareamento da extensão do Chrome',
    ru: 'Сопряжение расширения Chrome', tr: 'Chrome uzantısı eşleştirme', zh: 'Chrome 扩展配对',
  },
  'pairing.message': {
    ar: 'تطلب إضافة Chrome الوصول إلى بيانات اعتمادك.',
    de: 'Eine Chrome-Erweiterung fordert Zugriff auf Ihre Anmeldedaten an.',
    en: 'A Chrome extension is requesting access to your credentials.',
    es: 'Una extensión de Chrome solicita acceso a sus credenciales.',
    fr: "Une extension Chrome demande l'accès à vos identifiants.",
    it: "Un'estensione di Chrome richiede l'accesso alle tue credenziali.",
    ja: 'Chrome 拡張機能が認証情報へのアクセスを要求しています。',
    ko: 'Chrome 확장 프로그램이 자격 증명에 대한 액세스를 요청하고 있습니다.',
    pt: 'Uma extensão do Chrome está solicitando acesso às suas credenciais.',
    ru: 'Расширение Chrome запрашивает доступ к вашим учётным данным.',
    tr: 'Bir Chrome uzantısı kimlik bilgilerinize erişim istiyor.',
    zh: '一个 Chrome 扩展正在请求访问您的凭据。',
  },
  'pairing.detail': {
    ar: 'معرّف الإضافة:\n{{extId}}\n\nتحقق من أنه يطابق إضافة RDVAULT المثبتة (chrome://extensions).\nلا تسمح إلا إذا كنت قد ثبّت الإضافة أو فتحتها للتو.',
    de: 'Erweiterungs-ID:\n{{extId}}\n\nPrüfen Sie, ob sie mit der installierten RDVAULT-Erweiterung übereinstimmt (chrome://extensions).\nLassen Sie den Zugriff nur zu, wenn Sie die Erweiterung gerade installiert oder geöffnet haben.',
    en: 'Extension ID:\n{{extId}}\n\nCheck that it matches the installed RDVAULT extension (chrome://extensions).\nOnly allow if you have just installed or opened the extension.',
    es: 'Identificador de la extensión:\n{{extId}}\n\nCompruebe que corresponde a la extensión RDVAULT instalada (chrome://extensions).\nPermita el acceso solo si acaba de instalar o abrir la extensión.',
    fr: "Identifiant de l'extension :\n{{extId}}\n\nVérifiez qu'il correspond à l'extension RDVAULT installée (chrome://extensions).\nN'autorisez que si vous venez d'installer ou d'ouvrir l'extension.",
    it: "Identificativo dell'estensione:\n{{extId}}\n\nVerifica che corrisponda all'estensione RDVAULT installata (chrome://extensions).\nConsenti solo se hai appena installato o aperto l'estensione.",
    ja: '拡張機能 ID:\n{{extId}}\n\nインストール済みの RDVAULT 拡張機能と一致することを確認してください (chrome://extensions)。\n拡張機能をインストールした、または開いた直後の場合にのみ許可してください。',
    ko: '확장 프로그램 ID:\n{{extId}}\n\n설치된 RDVAULT 확장 프로그램과 일치하는지 확인하세요 (chrome://extensions).\n확장 프로그램을 방금 설치했거나 열었을 때만 허용하세요.',
    pt: 'Identificador da extensão:\n{{extId}}\n\nVerifique se ele corresponde à extensão RDVAULT instalada (chrome://extensions).\nSó permita se você acabou de instalar ou abrir a extensão.',
    ru: 'Идентификатор расширения:\n{{extId}}\n\nУбедитесь, что он совпадает с установленным расширением RDVAULT (chrome://extensions).\nРазрешайте доступ, только если вы только что установили или открыли расширение.',
    tr: 'Uzantı kimliği:\n{{extId}}\n\nYüklü RDVAULT uzantısıyla eşleştiğini doğrulayın (chrome://extensions).\nYalnızca uzantıyı yeni yüklediyseniz veya açtıysanız izin verin.',
    zh: '扩展 ID：\n{{extId}}\n\n请确认它与已安装的 RDVAULT 扩展一致 (chrome://extensions)。\n仅当您刚刚安装或打开该扩展时才允许。',
  },

  // ----- Clé d'hôte SSH inconnue lors de l'audit SSH (main.js) -----
  'hostKey.title': {
    ar: 'مفتاح مضيف SSH غير معروف', de: 'Unbekannter SSH-Host-Key', en: 'Unknown SSH host key',
    es: 'Clave de host SSH desconocida', fr: "Clé d'hôte SSH inconnue", it: 'Chiave host SSH sconosciuta',
    ja: '不明な SSH ホスト鍵', ko: '알 수 없는 SSH 호스트 키', pt: 'Chave de host SSH desconhecida',
    ru: 'Неизвестный ключ хоста SSH', tr: 'Bilinmeyen SSH ana bilgisayar anahtarı', zh: '未知的 SSH 主机密钥',
  },
  'hostKey.message': {
    ar: 'مفتاح مضيف SSH غير معروف لـ {{host}}:{{port}}',
    de: 'Unbekannter SSH-Host-Key für {{host}}:{{port}}',
    en: 'Unknown SSH host key for {{host}}:{{port}}',
    es: 'Clave de host SSH desconocida para {{host}}:{{port}}',
    fr: "Clé d'hôte SSH inconnue pour {{host}}:{{port}}",
    it: 'Chiave host SSH sconosciuta per {{host}}:{{port}}',
    ja: '{{host}}:{{port}} の SSH ホスト鍵が不明です',
    ko: '{{host}}:{{port}}의 SSH 호스트 키를 알 수 없습니다',
    pt: 'Chave de host SSH desconhecida para {{host}}:{{port}}',
    ru: 'Неизвестный ключ хоста SSH для {{host}}:{{port}}',
    tr: '{{host}}:{{port}} için bilinmeyen SSH ana bilgisayar anahtarı',
    zh: '{{host}}:{{port}} 的 SSH 主机密钥未知',
  },
  'hostKey.detail': {
    ar: 'بصمة مفتاح المضيف:\n{{fingerprint}}\n\nقارنها ببصمة الخادم (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nإذا تذكّرت هذا المفتاح، فسيُرفض أي اتصال لاحق بمفتاح مختلف.',
    de: 'Fingerabdruck des Host-Keys:\n{{fingerprint}}\n\nVergleichen Sie ihn mit dem des Servers (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nWenn Sie ihn speichern, wird jede spätere Verbindung mit einem anderen Schlüssel abgelehnt.',
    en: "Host key fingerprint:\n{{fingerprint}}\n\nCompare it with the server's (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nIf you remember it, any later connection with a different key will be refused.",
    es: 'Huella de la clave de host:\n{{fingerprint}}\n\nCompárela con la del servidor (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nSi la recuerda, cualquier conexión posterior con una clave distinta será rechazada.',
    fr: "Empreinte de la clé d'hôte :\n{{fingerprint}}\n\nComparez-la avec celle du serveur (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nSi vous la mémorisez, toute connexion ultérieure avec une clé différente sera refusée.",
    it: 'Impronta della chiave host:\n{{fingerprint}}\n\nConfrontala con quella del server (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nSe la memorizzi, ogni connessione successiva con una chiave diversa sarà rifiutata.',
    ja: 'ホスト鍵のフィンガープリント:\n{{fingerprint}}\n\nサーバー側のフィンガープリントと比較してください (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub)。\n記憶すると、以後異なる鍵での接続はすべて拒否されます。',
    ko: '호스트 키 지문:\n{{fingerprint}}\n\n서버의 지문과 비교하세요 (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\n이 키를 기억하면 이후 다른 키를 사용하는 모든 연결이 거부됩니다.',
    pt: 'Impressão digital da chave de host:\n{{fingerprint}}\n\nCompare-a com a do servidor (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nSe você memorizá-la, qualquer conexão posterior com uma chave diferente será recusada.',
    ru: 'Отпечаток ключа хоста:\n{{fingerprint}}\n\nСравните его с отпечатком на сервере (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nЕсли вы его запомните, любое последующее подключение с другим ключом будет отклонено.',
    tr: 'Ana bilgisayar anahtarı parmak izi:\n{{fingerprint}}\n\nSunucudakiyle karşılaştırın (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).\nHatırlarsanız, farklı bir anahtarla yapılan sonraki her bağlantı reddedilir.',
    zh: '主机密钥指纹：\n{{fingerprint}}\n\n请将其与服务器上的指纹进行比较 (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub)。\n如果记住该密钥，之后使用其他密钥的任何连接都将被拒绝。',
  },

  // ----- Accès à un secret par la CLI mvault (cliServer.js) -----
  'cliAccess.title': {
    ar: 'الوصول إلى سر — واجهة سطر الأوامر mvault', de: 'Zugriff auf Geheimnis — mvault-CLI',
    en: 'Secret access — mvault CLI', es: 'Acceso a secreto — CLI mvault', fr: 'Accès secret — CLI mvault',
    it: 'Accesso al segreto — CLI mvault', ja: 'シークレットへのアクセス — mvault CLI', ko: '시크릿 액세스 — mvault CLI',
    pt: 'Acesso a segredo — CLI mvault', ru: 'Доступ к секрету — CLI mvault', tr: 'Sırra erişim — mvault CLI',
    zh: '机密访问 — mvault CLI',
  },
  'cliAccess.message': {
    ar: 'تطلب عملية من واجهة سطر الأوامر الوصول إلى سر في Vault.',
    de: 'Ein CLI-Prozess fordert Zugriff auf ein Vault-Geheimnis an.',
    en: 'A CLI process is requesting access to a Vault secret.',
    es: 'Un proceso de la CLI solicita acceso a un secreto de Vault.',
    fr: "Un processus CLI demande l'accès à un secret Vault.",
    it: "Un processo CLI richiede l'accesso a un segreto di Vault.",
    ja: 'CLI プロセスが Vault のシークレットへのアクセスを要求しています。',
    ko: 'CLI 프로세스가 Vault 시크릿에 대한 액세스를 요청하고 있습니다.',
    pt: 'Um processo da CLI está solicitando acesso a um segredo do Vault.',
    ru: 'Процесс CLI запрашивает доступ к секрету Vault.',
    tr: 'Bir CLI işlemi bir Vault sırrına erişim istiyor.',
    zh: '一个 CLI 进程正在请求访问 Vault 机密。',
  },
  'cliAccess.detail': {
    ar: 'المسار: {{path}}\n\nهل تسمح بالوصول؟', de: 'Pfad: {{path}}\n\nZugriff zulassen?',
    en: 'Path: {{path}}\n\nAllow access?', es: 'Ruta: {{path}}\n\n¿Permitir el acceso?',
    fr: "Chemin : {{path}}\n\nAutoriser l'accès ?", it: "Percorso: {{path}}\n\nConsentire l'accesso?",
    ja: 'パス: {{path}}\n\nアクセスを許可しますか？', ko: '경로: {{path}}\n\n액세스를 허용하시겠습니까?',
    pt: 'Caminho: {{path}}\n\nPermitir o acesso?', ru: 'Путь: {{path}}\n\nРазрешить доступ?',
    tr: 'Yol: {{path}}\n\nErişime izin verilsin mi?', zh: '路径：{{path}}\n\n是否允许访问？',
  },
  // Rafale d'accès auto-approuvés : la confirmation humaine est forcée (détection de rafale)
  'cliAccess.burst': {
    ar: '{{path}} [دفعة: {{count}} عملية وصول خلال {{seconds}} ث]',
    de: '{{path}} [Häufung: {{count}} Zugriffe in {{seconds}} s]',
    en: '{{path}} [burst: {{count}} accesses in {{seconds}}s]',
    es: '{{path}} [ráfaga: {{count}} accesos en {{seconds}} s]',
    fr: '{{path}} [burst: {{count}} accès en {{seconds}}s]',
    it: '{{path}} [raffica: {{count}} accessi in {{seconds}} s]',
    ja: '{{path}} [集中アクセス: {{seconds}} 秒間に {{count}} 回]',
    ko: '{{path}} [집중 액세스: {{seconds}}초 동안 {{count}}회]',
    pt: '{{path}} [rajada: {{count}} acessos em {{seconds}} s]',
    ru: '{{path}} [всплеск: {{count}} обращений за {{seconds}} с]',
    tr: '{{path}} [yoğun erişim: {{seconds}} sn içinde {{count}} erişim]',
    zh: '{{path}} [突发：{{seconds}} 秒内访问 {{count}} 次]',
  },

  // ----- Clé d'hôte SSH inconnue demandée par la CLI mvault (cliServer.js) -----
  'cliHostKey.title': {
    ar: 'مفتاح مضيف SSH غير معروف — واجهة سطر الأوامر mvault', de: 'Unbekannter SSH-Host-Key — mvault-CLI',
    en: 'Unknown SSH host key — mvault CLI', es: 'Clave de host SSH desconocida — CLI mvault',
    fr: "Clé d'hôte SSH inconnue — CLI mvault", it: 'Chiave host SSH sconosciuta — CLI mvault',
    ja: '不明な SSH ホスト鍵 — mvault CLI', ko: '알 수 없는 SSH 호스트 키 — mvault CLI',
    pt: 'Chave de host SSH desconhecida — CLI mvault', ru: 'Неизвестный ключ хоста SSH — CLI mvault',
    tr: 'Bilinmeyen SSH ana bilgisayar anahtarı — mvault CLI', zh: '未知的 SSH 主机密钥 — mvault CLI',
  },
  'cliHostKey.message': {
    ar: 'أول اتصال SSH بهذا المضيف: لم يتم تذكر مفتاحه بعد.',
    de: 'Erste SSH-Verbindung zu diesem Host: Sein Schlüssel ist noch nicht gespeichert.',
    en: 'First SSH connection to this host: its key is not remembered yet.',
    es: 'Primera conexión SSH a este host: su clave aún no está guardada.',
    fr: "Première connexion SSH à cet hôte : sa clé n'est pas encore mémorisée.",
    it: 'Prima connessione SSH a questo host: la sua chiave non è ancora memorizzata.',
    ja: 'このホストへの初めての SSH 接続です。ホスト鍵はまだ記憶されていません。',
    ko: '이 호스트에 대한 첫 SSH 연결입니다. 호스트 키가 아직 기억되지 않았습니다.',
    pt: 'Primeira conexão SSH a este host: a chave dele ainda não foi memorizada.',
    ru: 'Первое SSH-подключение к этому хосту: его ключ ещё не запомнен.',
    tr: 'Bu ana bilgisayara ilk SSH bağlantısı: anahtarı henüz hatırlanmadı.',
    zh: '首次通过 SSH 连接此主机：其密钥尚未被记住。',
  },
  'cliHostKey.detail': {
    ar: 'المضيف: {{host}}:{{port}}\nالبصمة: {{fingerprint}}\n\nهل تريد تذكر هذا المفتاح والمتابعة؟',
    de: 'Host: {{host}}:{{port}}\nFingerabdruck: {{fingerprint}}\n\nDiesen Schlüssel speichern und fortfahren?',
    en: 'Host: {{host}}:{{port}}\nFingerprint: {{fingerprint}}\n\nRemember this key and continue?',
    es: 'Host: {{host}}:{{port}}\nHuella: {{fingerprint}}\n\n¿Recordar esta clave y continuar?',
    fr: 'Hôte : {{host}}:{{port}}\nEmpreinte : {{fingerprint}}\n\nMémoriser cette clé et continuer ?',
    it: 'Host: {{host}}:{{port}}\nImpronta: {{fingerprint}}\n\nMemorizzare questa chiave e continuare?',
    ja: 'ホスト: {{host}}:{{port}}\nフィンガープリント: {{fingerprint}}\n\nこの鍵を記憶して続行しますか？',
    ko: '호스트: {{host}}:{{port}}\n지문: {{fingerprint}}\n\n이 키를 기억하고 계속하시겠습니까?',
    pt: 'Host: {{host}}:{{port}}\nImpressão digital: {{fingerprint}}\n\nMemorizar esta chave e continuar?',
    ru: 'Хост: {{host}}:{{port}}\nОтпечаток: {{fingerprint}}\n\nЗапомнить этот ключ и продолжить?',
    tr: 'Ana bilgisayar: {{host}}:{{port}}\nParmak izi: {{fingerprint}}\n\nBu anahtar hatırlansın ve devam edilsin mi?',
    zh: '主机：{{host}}:{{port}}\n指纹：{{fingerprint}}\n\n是否记住此密钥并继续？',
  },

  // ----- Échec de chargement de l'interface (showErrorBox, main.js) -----
  'load.failed': {
    ar: 'فشل التحميل', de: 'Laden fehlgeschlagen', en: 'Loading failed', es: 'Error de carga',
    fr: 'Chargement échoué', it: 'Caricamento non riuscito', ja: '読み込みに失敗しました', ko: '로드 실패',
    pt: 'Falha ao carregar', ru: 'Ошибка загрузки', tr: 'Yükleme başarısız', zh: '加载失败',
  },
  'load.failedDev': {
    ar: 'فشل التحميل (التطوير)', de: 'Laden fehlgeschlagen (Entwicklung)', en: 'Loading failed (dev)',
    es: 'Error de carga (desarrollo)', fr: 'Chargement échoué (dev)', it: 'Caricamento non riuscito (sviluppo)',
    ja: '読み込みに失敗しました (開発)', ko: '로드 실패 (개발)', pt: 'Falha ao carregar (desenvolvimento)',
    ru: 'Ошибка загрузки (разработка)', tr: 'Yükleme başarısız (geliştirme)', zh: '加载失败 (开发)',
  },

  // ----- Erreurs IPC affichées telles quelles dans un toast (urlHandler.js, AdminPanel.jsx) -----
  'error.invalidHost': {
    ar: 'اسم مضيف غير صالح', de: 'Ungültiger Hostname', en: 'Invalid host name', es: 'Nombre de host no válido',
    fr: "Nom d'hôte invalide", it: 'Nome host non valido', ja: 'ホスト名が無効です', ko: '잘못된 호스트 이름',
    pt: 'Nome de host inválido', ru: 'Недопустимое имя хоста', tr: 'Geçersiz ana bilgisayar adı', zh: '主机名无效',
  },
  'error.invalidUsername': {
    ar: 'اسم مستخدم غير صالح', de: 'Ungültiger Benutzername', en: 'Invalid user name', es: 'Nombre de usuario no válido',
    fr: "Nom d'utilisateur invalide", it: 'Nome utente non valido', ja: 'ユーザー名が無効です', ko: '잘못된 사용자 이름',
    pt: 'Nome de usuário inválido', ru: 'Недопустимое имя пользователя', tr: 'Geçersiz kullanıcı adı', zh: '用户名无效',
  },
  'error.invalidPort': {
    ar: 'منفذ غير صالح (1-65535)', de: 'Ungültiger Port (1-65535)', en: 'Invalid port (1-65535)',
    es: 'Puerto no válido (1-65535)', fr: 'Port invalide (1-65535)', it: 'Porta non valida (1-65535)',
    ja: 'ポートが無効です (1-65535)', ko: '잘못된 포트 (1-65535)', pt: 'Porta inválida (1-65535)',
    ru: 'Недопустимый порт (1-65535)', tr: 'Geçersiz bağlantı noktası (1-65535)', zh: '端口无效 (1-65535)',
  },
  'error.puttyNotFound': {
    ar: 'لم يتم العثور على PuTTY. يرجى تثبيت PuTTY.', de: 'PuTTY nicht gefunden. Bitte installieren Sie PuTTY.',
    en: 'PuTTY not found. Please install PuTTY.', es: 'No se encontró PuTTY. Instale PuTTY.',
    fr: 'PuTTY non trouvé. Veuillez installer PuTTY.', it: 'PuTTY non trovato. Installa PuTTY.',
    ja: 'PuTTY が見つかりません。PuTTY をインストールしてください。', ko: 'PuTTY를 찾을 수 없습니다. PuTTY를 설치하세요.',
    pt: 'PuTTY não encontrado. Instale o PuTTY.', ru: 'PuTTY не найден. Установите PuTTY.',
    tr: "PuTTY bulunamadı. Lütfen PuTTY'yi yükleyin.", zh: '未找到 PuTTY。请安装 PuTTY。',
  },
  'error.sshOpen': {
    ar: 'خطأ أثناء فتح اتصال SSH', de: 'Fehler beim Öffnen der SSH-Verbindung', en: 'Error opening the SSH connection',
    es: 'Error al abrir la conexión SSH', fr: 'Erreur ouverture connexion SSH', it: "Errore durante l'apertura della connessione SSH",
    ja: 'SSH 接続を開く際にエラーが発生しました', ko: 'SSH 연결을 여는 중 오류가 발생했습니다', pt: 'Erro ao abrir a conexão SSH',
    ru: 'Ошибка при открытии SSH-подключения', tr: 'SSH bağlantısı açılırken hata oluştu', zh: '打开 SSH 连接时出错',
  },
  'error.urlSchemeNotAllowed': {
    ar: 'بروتوكول URL غير مسموح به', de: 'URL-Protokoll nicht erlaubt', en: 'URL protocol not allowed',
    es: 'Protocolo de URL no permitido', fr: 'Protocole URL non autorisé', it: 'Protocollo URL non consentito',
    ja: '許可されていない URL プロトコルです', ko: '허용되지 않는 URL 프로토콜입니다', pt: 'Protocolo de URL não permitido',
    ru: 'Протокол URL не разрешён', tr: 'URL protokolüne izin verilmiyor', zh: '不允许的 URL 协议',
  },
  'error.linkOpen': {
    ar: 'خطأ أثناء فتح الرابط', de: 'Fehler beim Öffnen des Links', en: 'Error opening the link',
    es: 'Error al abrir el enlace', fr: 'Erreur ouverture lien', it: "Errore durante l'apertura del link",
    ja: 'リンクを開く際にエラーが発生しました', ko: '링크를 여는 중 오류가 발생했습니다', pt: 'Erro ao abrir o link',
    ru: 'Ошибка при открытии ссылки', tr: 'Bağlantı açılırken hata oluştu', zh: '打开链接时出错',
  },
  'error.rdpDomainInvalid': {
    ar: 'نطاق RDP غير صالح', de: 'Ungültige RDP-Domäne', en: 'Invalid RDP domain', es: 'Dominio RDP no válido',
    fr: 'Domaine RDP invalide', it: 'Dominio RDP non valido', ja: 'RDP ドメインが無効です', ko: '잘못된 RDP 도메인',
    pt: 'Domínio RDP inválido', ru: 'Недопустимый домен RDP', tr: 'Geçersiz RDP etki alanı', zh: 'RDP 域无效',
  },
  'error.rdpOpen': {
    ar: 'خطأ أثناء فتح اتصال RDP', de: 'Fehler beim Öffnen der RDP-Verbindung', en: 'Error opening the RDP connection',
    es: 'Error al abrir la conexión RDP', fr: 'Erreur ouverture connexion RDP', it: "Errore durante l'apertura della connessione RDP",
    ja: 'RDP 接続を開く際にエラーが発生しました', ko: 'RDP 연결을 여는 중 오류가 발생했습니다', pt: 'Erro ao abrir a conexão RDP',
    ru: 'Ошибка при открытии RDP-подключения', tr: 'RDP bağlantısı açılırken hata oluştu', zh: '打开 RDP 连接时出错',
  },
  'error.sftpClientMissing': {
    ar: 'لا يوجد FileZilla ولا WinSCP مثبتًا على هذا النظام',
    de: 'Weder FileZilla noch WinSCP ist auf diesem System installiert',
    en: 'Neither FileZilla nor WinSCP is installed on this system',
    es: 'Ni FileZilla ni WinSCP están instalados en este sistema',
    fr: "FileZilla ou WinSCP n'est pas installé sur ce système",
    it: 'Né FileZilla né WinSCP sono installati su questo sistema',
    ja: 'このシステムには FileZilla も WinSCP もインストールされていません',
    ko: '이 시스템에 FileZilla와 WinSCP가 모두 설치되어 있지 않습니다',
    pt: 'Nem o FileZilla nem o WinSCP estão instalados neste sistema',
    ru: 'В системе не установлен ни FileZilla, ни WinSCP',
    tr: 'Bu sistemde ne FileZilla ne de WinSCP yüklü',
    zh: '此系统上未安装 FileZilla 或 WinSCP',
  },
  'error.sftpOpen': {
    ar: 'خطأ أثناء فتح اتصال SFTP', de: 'Fehler beim Öffnen der SFTP-Verbindung', en: 'Error opening the SFTP connection',
    es: 'Error al abrir la conexión SFTP', fr: 'Erreur ouverture connexion SFTP', it: "Errore durante l'apertura della connessione SFTP",
    ja: 'SFTP 接続を開く際にエラーが発生しました', ko: 'SFTP 연결을 여는 중 오류가 발생했습니다', pt: 'Erro ao abrir a conexão SFTP',
    ru: 'Ошибка при открытии SFTP-подключения', tr: 'SFTP bağlantısı açılırken hata oluştu', zh: '打开 SFTP 连接时出错',
  },
  'error.browserUnknown': {
    ar: 'متصفح غير معروف', de: 'Browser nicht erkannt', en: 'Unrecognized browser', es: 'Navegador no reconocido',
    fr: 'Navigateur non reconnu', it: 'Browser non riconosciuto', ja: '認識できないブラウザーです', ko: '인식할 수 없는 브라우저입니다',
    pt: 'Navegador não reconhecido', ru: 'Браузер не распознан', tr: 'Tarayıcı tanınmadı', zh: '无法识别的浏览器',
  },
  'error.invalidUrl': {
    ar: 'عنوان URL غير صالح', de: 'Ungültige URL', en: 'Invalid URL', es: 'URL no válida', fr: 'URL invalide',
    it: 'URL non valido', ja: 'URL が無効です', ko: '잘못된 URL', pt: 'URL inválida', ru: 'Недопустимый URL',
    tr: 'Geçersiz URL', zh: 'URL 无效',
  },
  'error.urlOpen': {
    ar: 'خطأ أثناء فتح عنوان URL', de: 'Fehler beim Öffnen der URL', en: 'Error opening the URL', es: 'Error al abrir la URL',
    fr: 'Erreur ouverture URL', it: "Errore durante l'apertura dell'URL", ja: 'URL を開く際にエラーが発生しました',
    ko: 'URL을 여는 중 오류가 발생했습니다', pt: 'Erro ao abrir a URL', ru: 'Ошибка при открытии URL',
    tr: 'URL açılırken hata oluştu', zh: '打开 URL 时出错',
  },
  'error.hostKeyPromptAborted': {
    ar: 'انقطع اتصال SSH أثناء التحقق من مفتاح المضيف (لم يتم تذكر أي مفتاح): أعد تشغيل القراءة.',
    de: 'SSH-Verbindung während der Prüfung des Host-Keys unterbrochen (kein Schlüssel gespeichert): Starten Sie das Lesen erneut.',
    en: 'SSH connection interrupted during host key verification (no key remembered): run the read again.',
    es: 'Conexión SSH interrumpida durante la verificación de la clave de host (no se guardó ninguna clave): vuelva a iniciar la lectura.',
    fr: "Connexion SSH interrompue pendant la vérification de la clé d'hôte (aucune clé mémorisée) : relancez la lecture.",
    it: 'Connessione SSH interrotta durante la verifica della chiave host (nessuna chiave memorizzata): riavvia la lettura.',
    ja: 'ホスト鍵の確認中に SSH 接続が中断されました (鍵は記憶されていません)。読み込みをやり直してください。',
    ko: '호스트 키 확인 중 SSH 연결이 중단되었습니다 (기억된 키 없음). 읽기를 다시 실행하세요.',
    pt: 'Conexão SSH interrompida durante a verificação da chave de host (nenhuma chave memorizada): execute a leitura novamente.',
    ru: 'SSH-подключение прервано во время проверки ключа хоста (ключ не запомнен): повторите чтение.',
    tr: 'Ana bilgisayar anahtarı doğrulanırken SSH bağlantısı kesildi (hiçbir anahtar hatırlanmadı): okumayı yeniden başlatın.',
    zh: '验证主机密钥时 SSH 连接中断 (未记住任何密钥)：请重新读取。',
  },

  // ----- Clé d'hôte SSH refusée (sshBroker.js) : erreurs HOST_KEY_* / KNOWN_HOSTS_* affichées telles quelles
  // dans un toast (AdminPanel, lecture SSH des journaux d'audit) et en « Détail » par mvault -----
  'sshHostKey.changed': {
    ar: 'تغيّر مفتاح مضيف SSH لـ {{where}}: المتوقع {{expected}}، والملاحَظ {{observed}} (هجوم وسيط محتمل)',
    de: 'Der SSH-Host-Key von {{where}} HAT SICH GEÄNDERT: erwartet {{expected}}, festgestellt {{observed}} (möglicher Man-in-the-Middle-Angriff)',
    en: 'The SSH host key of {{where}} HAS CHANGED: expected {{expected}}, observed {{observed}} (possible man-in-the-middle attack)',
    es: 'La clave de host SSH de {{where}} HA CAMBIADO: se esperaba {{expected}}, se observó {{observed}} (posible ataque de intermediario)',
    fr: "La clé d'hôte SSH de {{where}} A CHANGÉ : attendue {{expected}}, observée {{observed}} (possible attaque de l'homme du milieu)",
    it: 'La chiave host SSH di {{where}} È CAMBIATA: attesa {{expected}}, rilevata {{observed}} (possibile attacco man-in-the-middle)',
    ja: '{{where}} の SSH ホスト鍵が変更されました: 期待値 {{expected}}、検出値 {{observed}} (中間者攻撃の可能性があります)',
    ko: '{{where}}의 SSH 호스트 키가 변경되었습니다: 예상 {{expected}}, 관찰 {{observed}} (중간자 공격 가능성)',
    pt: 'A chave de host SSH de {{where}} MUDOU: esperada {{expected}}, observada {{observed}} (possível ataque man-in-the-middle)',
    ru: 'Ключ хоста SSH для {{where}} ИЗМЕНИЛСЯ: ожидался {{expected}}, получен {{observed}} (возможна атака «человек посередине»)',
    tr: '{{where}} için SSH ana bilgisayar anahtarı DEĞİŞTİ: beklenen {{expected}}, gözlemlenen {{observed}} (olası ortadaki adam saldırısı)',
    zh: '{{where}} 的 SSH 主机密钥已更改：预期 {{expected}}，实际 {{observed}} (可能存在中间人攻击)',
  },
  // Clé changée alors qu'une empreinte est épinglée : l'épinglage ne remplace pas la clé mémorisée
  'sshHostKey.changedPinned': {
    ar: 'تغيّر مفتاح مضيف SSH لـ {{where}}: المتوقع {{expected}}، والملاحَظ {{observed}} (هجوم وسيط محتمل)؛ البصمة المثبّتة لا تحلّ محل المفتاح المحفوظ: احذف الإدخال من known_hosts إذا كان التغيير مشروعًا',
    de: 'Der SSH-Host-Key von {{where}} HAT SICH GEÄNDERT: erwartet {{expected}}, festgestellt {{observed}} (möglicher Man-in-the-Middle-Angriff); der angeheftete Fingerabdruck ersetzt den gespeicherten Schlüssel nicht: Entfernen Sie den Eintrag aus known_hosts, wenn die Änderung legitim ist',
    en: 'The SSH host key of {{where}} HAS CHANGED: expected {{expected}}, observed {{observed}} (possible man-in-the-middle attack); the pinned fingerprint does not replace the remembered key: remove the known_hosts entry if the change is legitimate',
    es: 'La clave de host SSH de {{where}} HA CAMBIADO: se esperaba {{expected}}, se observó {{observed}} (posible ataque de intermediario); la huella fijada no sustituye a la clave guardada: elimine la entrada de known_hosts si el cambio es legítimo',
    fr: "La clé d'hôte SSH de {{where}} A CHANGÉ : attendue {{expected}}, observée {{observed}} (possible attaque de l'homme du milieu) ; l'empreinte épinglée ne remplace pas la clé mémorisée : supprimez l'entrée de known_hosts si le changement est légitime",
    it: "La chiave host SSH di {{where}} È CAMBIATA: attesa {{expected}}, rilevata {{observed}} (possibile attacco man-in-the-middle); l'impronta fissata non sostituisce la chiave memorizzata: rimuovi la voce da known_hosts se la modifica è legittima",
    ja: '{{where}} の SSH ホスト鍵が変更されました: 期待値 {{expected}}、検出値 {{observed}} (中間者攻撃の可能性があります)。固定されたフィンガープリントは記憶済みの鍵を置き換えません。変更が正当な場合は known_hosts のエントリを削除してください',
    ko: '{{where}}의 SSH 호스트 키가 변경되었습니다: 예상 {{expected}}, 관찰 {{observed}} (중간자 공격 가능성). 고정된 지문은 기억된 키를 대체하지 않습니다. 변경이 정당하면 known_hosts 항목을 삭제하세요',
    pt: 'A chave de host SSH de {{where}} MUDOU: esperada {{expected}}, observada {{observed}} (possível ataque man-in-the-middle); a impressão digital fixada não substitui a chave memorizada: remova a entrada de known_hosts se a mudança for legítima',
    ru: 'Ключ хоста SSH для {{where}} ИЗМЕНИЛСЯ: ожидался {{expected}}, получен {{observed}} (возможна атака «человек посередине»); закреплённый отпечаток не заменяет запомненный ключ: удалите запись из known_hosts, если изменение законно',
    tr: '{{where}} için SSH ana bilgisayar anahtarı DEĞİŞTİ: beklenen {{expected}}, gözlemlenen {{observed}} (olası ortadaki adam saldırısı); sabitlenmiş parmak izi hatırlanan anahtarın yerini almaz: değişiklik meşruysa known_hosts kaydını silin',
    zh: '{{where}} 的 SSH 主机密钥已更改：预期 {{expected}}，实际 {{observed}} (可能存在中间人攻击)；固定的指纹不会替换已记住的密钥：如果更改是合法的，请删除 known_hosts 中的条目',
  },
  'sshHostKey.mismatch': {
    ar: 'بصمة مفتاح مضيف SSH غير متوقعة لـ {{where}}: المتوقعة {{expected}}، والملاحَظة {{observed}}',
    de: 'Unerwarteter Fingerabdruck des SSH-Host-Keys für {{where}}: erwartet {{expected}}, festgestellt {{observed}}',
    en: 'Unexpected SSH host key fingerprint for {{where}}: expected {{expected}}, observed {{observed}}',
    es: 'Huella de clave de host SSH inesperada para {{where}}: se esperaba {{expected}}, se observó {{observed}}',
    fr: "Empreinte de clé d'hôte SSH inattendue pour {{where}} : attendue {{expected}}, observée {{observed}}",
    it: 'Impronta della chiave host SSH inattesa per {{where}}: attesa {{expected}}, rilevata {{observed}}',
    ja: '{{where}} の SSH ホスト鍵のフィンガープリントが想定と異なります: 期待値 {{expected}}、検出値 {{observed}}',
    ko: '{{where}}의 SSH 호스트 키 지문이 예상과 다릅니다: 예상 {{expected}}, 관찰 {{observed}}',
    pt: 'Impressão digital da chave de host SSH inesperada para {{where}}: esperada {{expected}}, observada {{observed}}',
    ru: 'Неожиданный отпечаток ключа хоста SSH для {{where}}: ожидался {{expected}}, получен {{observed}}',
    tr: '{{where}} için beklenmeyen SSH ana bilgisayar anahtarı parmak izi: beklenen {{expected}}, gözlemlenen {{observed}}',
    zh: '{{where}} 的 SSH 主机密钥指纹与预期不符：预期 {{expected}}，实际 {{observed}}',
  },
  // Rappel de l'appelant en erreur (motif technique entre parenthèses)
  'sshHostKey.rejected': {
    ar: 'تم رفض مفتاح مضيف SSH لـ {{where}} ({{reason}})', de: 'SSH-Host-Key von {{where}} abgelehnt ({{reason}})',
    en: 'SSH host key of {{where}} refused ({{reason}})', es: 'Clave de host SSH de {{where}} rechazada ({{reason}})',
    fr: "Clé d'hôte SSH de {{where}} refusée ({{reason}})", it: 'Chiave host SSH di {{where}} rifiutata ({{reason}})',
    ja: '{{where}} の SSH ホスト鍵が拒否されました ({{reason}})', ko: '{{where}}의 SSH 호스트 키가 거부되었습니다 ({{reason}})',
    pt: 'Chave de host SSH de {{where}} recusada ({{reason}})', ru: 'Ключ хоста SSH для {{where}} отклонён ({{reason}})',
    tr: '{{where}} için SSH ana bilgisayar anahtarı reddedildi ({{reason}})', zh: '{{where}} 的 SSH 主机密钥被拒绝 ({{reason}})',
  },
  'sshHostKey.rejectedByUser': {
    ar: 'رفض المستخدم مفتاح مضيف SSH لـ {{where}} ({{observed}})', de: 'SSH-Host-Key von {{where}} vom Benutzer abgelehnt ({{observed}})',
    en: 'SSH host key of {{where}} refused by the user ({{observed}})', es: 'Clave de host SSH de {{where}} rechazada por el usuario ({{observed}})',
    fr: "Clé d'hôte SSH de {{where}} refusée par l'utilisateur ({{observed}})", it: "Chiave host SSH di {{where}} rifiutata dall'utente ({{observed}})",
    ja: '{{where}} の SSH ホスト鍵はユーザーによって拒否されました ({{observed}})', ko: '{{where}}의 SSH 호스트 키를 사용자가 거부했습니다 ({{observed}})',
    pt: 'Chave de host SSH de {{where}} recusada pelo usuário ({{observed}})', ru: 'Ключ хоста SSH для {{where}} отклонён пользователем ({{observed}})',
    tr: '{{where}} için SSH ana bilgisayar anahtarı kullanıcı tarafından reddedildi ({{observed}})', zh: '{{where}} 的 SSH 主机密钥被用户拒绝 ({{observed}})',
  },
  'sshHostKey.unknown': {
    ar: 'مفتاح مضيف SSH غير معروف لـ {{where}} ({{observed}}): لا توجد بصمة مثبّتة أو محفوظة',
    de: 'Unbekannter SSH-Host-Key für {{where}} ({{observed}}): kein angehefteter oder gespeicherter Fingerabdruck',
    en: 'Unknown SSH host key for {{where}} ({{observed}}): no pinned or remembered fingerprint',
    es: 'Clave de host SSH desconocida para {{where}} ({{observed}}): ninguna huella fijada ni guardada',
    fr: "Clé d'hôte SSH inconnue pour {{where}} ({{observed}}) : aucune empreinte épinglée ni mémorisée",
    it: 'Chiave host SSH sconosciuta per {{where}} ({{observed}}): nessuna impronta fissata né memorizzata',
    ja: '{{where}} の SSH ホスト鍵が不明です ({{observed}}): 固定または記憶されたフィンガープリントがありません',
    ko: '{{where}}의 알 수 없는 SSH 호스트 키 ({{observed}}): 고정되거나 기억된 지문이 없습니다',
    pt: 'Chave de host SSH desconhecida para {{where}} ({{observed}}): nenhuma impressão digital fixada nem memorizada',
    ru: 'Неизвестный ключ хоста SSH для {{where}} ({{observed}}): нет ни закреплённого, ни запомненного отпечатка',
    tr: '{{where}} için bilinmeyen SSH ana bilgisayar anahtarı ({{observed}}): sabitlenmiş veya hatırlanan parmak izi yok',
    zh: '{{where}} 的 SSH 主机密钥未知 ({{observed}})：没有固定或已记住的指纹',
  },
  // Clé différente présentée lors d'un renouvellement des clés (re-KEX) EN COURS de session
  'sshHostKey.changedRekey': {
    ar: 'تغيّر مفتاح مضيف SSH لـ {{where}} أثناء الجلسة (تجديد المفاتيح): المتوقع {{expected}}، والملاحَظ {{observed}}؛ تم قطع الاتصال، ولم يتم تعديل known_hosts',
    de: 'Der SSH-Host-Key von {{where}} HAT SICH WÄHREND der Sitzung GEÄNDERT (Schlüsselerneuerung): erwartet {{expected}}, festgestellt {{observed}}; Verbindung unterbrochen, known_hosts wurde nicht geändert',
    en: 'The SSH host key of {{where}} CHANGED DURING the session (key renegotiation): expected {{expected}}, observed {{observed}}; connection interrupted, known_hosts was not modified',
    es: 'La clave de host SSH de {{where}} HA CAMBIADO DURANTE la sesión (renovación de claves): se esperaba {{expected}}, se observó {{observed}}; conexión interrumpida, known_hosts no se ha modificado',
    fr: "La clé d'hôte SSH de {{where}} A CHANGÉ EN COURS de session (renouvellement des clés) : attendue {{expected}}, observée {{observed}} ; connexion interrompue, known_hosts n'a pas été modifié",
    it: 'La chiave host SSH di {{where}} È CAMBIATA DURANTE la sessione (rinnovo delle chiavi): attesa {{expected}}, rilevata {{observed}}; connessione interrotta, known_hosts non è stato modificato',
    ja: '{{where}} の SSH ホスト鍵がセッション中に変更されました (鍵の再交換): 期待値 {{expected}}、検出値 {{observed}}。接続は中断されました。known_hosts は変更されていません',
    ko: '{{where}}의 SSH 호스트 키가 세션 도중 변경되었습니다 (키 재교환): 예상 {{expected}}, 관찰 {{observed}}. 연결이 중단되었으며 known_hosts는 수정되지 않았습니다',
    pt: 'A chave de host SSH de {{where}} MUDOU DURANTE a sessão (renovação de chaves): esperada {{expected}}, observada {{observed}}; conexão interrompida, known_hosts não foi modificado',
    ru: 'Ключ хоста SSH для {{where}} ИЗМЕНИЛСЯ ВО ВРЕМЯ сеанса (обновление ключей): ожидался {{expected}}, получен {{observed}}; подключение прервано, known_hosts не изменён',
    tr: '{{where}} için SSH ana bilgisayar anahtarı oturum SIRASINDA DEĞİŞTİ (anahtar yenileme): beklenen {{expected}}, gözlemlenen {{observed}}; bağlantı kesildi, known_hosts değiştirilmedi',
    zh: '{{where}} 的 SSH 主机密钥在会话期间发生更改 (密钥重新协商)：预期 {{expected}}，实际 {{observed}}；连接已中断，known_hosts 未被修改',
  },
  'sshHostKey.readError': {
    ar: 'تعذّرت قراءة مخزن مفاتيح مضيف SSH لـ {{where}}: {{reason}}',
    de: 'Der Speicher der SSH-Host-Keys für {{where}} kann nicht gelesen werden: {{reason}}',
    en: 'Cannot read the SSH host key store for {{where}}: {{reason}}',
    es: 'No se puede leer el almacén de claves de host SSH para {{where}}: {{reason}}',
    fr: "Impossible de lire la mémoire des clés d'hôte SSH pour {{where}} : {{reason}}",
    it: "Impossibile leggere l'archivio delle chiavi host SSH per {{where}}: {{reason}}",
    ja: '{{where}} の SSH ホスト鍵ストアを読み取れません: {{reason}}',
    ko: '{{where}}의 SSH 호스트 키 저장소를 읽을 수 없습니다: {{reason}}',
    pt: 'Não é possível ler o armazenamento de chaves de host SSH para {{where}}: {{reason}}',
    ru: 'Не удаётся прочитать хранилище ключей хостов SSH для {{where}}: {{reason}}',
    tr: '{{where}} için SSH ana bilgisayar anahtarı deposu okunamıyor: {{reason}}',
    zh: '无法读取 {{where}} 的 SSH 主机密钥存储：{{reason}}',
  },
  'sshHostKey.writeError': {
    ar: 'تعذّر حفظ مفتاح مضيف SSH لـ {{where}}: {{reason}}',
    de: 'Der SSH-Host-Key von {{where}} kann nicht gespeichert werden: {{reason}}',
    en: 'Cannot remember the SSH host key of {{where}}: {{reason}}',
    es: 'No se puede guardar la clave de host SSH de {{where}}: {{reason}}',
    fr: "Impossible de mémoriser la clé d'hôte SSH de {{where}} : {{reason}}",
    it: 'Impossibile memorizzare la chiave host SSH di {{where}}: {{reason}}',
    ja: '{{where}} の SSH ホスト鍵を記憶できません: {{reason}}',
    ko: '{{where}}의 SSH 호스트 키를 기억할 수 없습니다: {{reason}}',
    pt: 'Não é possível memorizar a chave de host SSH de {{where}}: {{reason}}',
    ru: 'Не удаётся запомнить ключ хоста SSH для {{where}}: {{reason}}',
    tr: '{{where}} için SSH ana bilgisayar anahtarı hatırlanamıyor: {{reason}}',
    zh: '无法记住 {{where}} 的 SSH 主机密钥：{{reason}}',
  },

  // ----- Sessions navigateur isolées (secureSession.js) : motif d'échec renvoyé au renderer (result.error),
  // affiché tel quel dans un toast (urlHandler, ShareRbiModal, App) -----
  'rbi.maxSessions': {
    ar: 'تم بلوغ الحد الأقصى لعدد جلسات RBI ({{max}})', de: 'Maximale Anzahl von RBI-Sitzungen erreicht ({{max}})',
    en: 'Maximum number of RBI sessions reached ({{max}})', es: 'Se alcanzó el número máximo de sesiones RBI ({{max}})',
    fr: 'Nombre maximum de sessions RBI atteint ({{max}})', it: 'Numero massimo di sessioni RBI raggiunto ({{max}})',
    ja: 'RBI セッションの最大数に達しました ({{max}})', ko: '최대 RBI 세션 수에 도달했습니다 ({{max}})',
    pt: 'Número máximo de sessões RBI atingido ({{max}})', ru: 'Достигнуто максимальное число сеансов RBI ({{max}})',
    tr: 'Azami RBI oturumu sayısına ulaşıldı ({{max}})', zh: '已达到 RBI 会话数上限 ({{max}})',
  },
  'rbi.downloadPolicy': {
    ar: 'تعذّر تطبيق سياسة التنزيل (CDP غير متاح)', de: 'Die Download-Richtlinie kann nicht angewendet werden (CDP nicht verfügbar)',
    en: 'Cannot apply the download policy (CDP unavailable)', es: 'No se puede aplicar la directiva de descargas (CDP no disponible)',
    fr: "Impossible d'appliquer la politique de téléchargement (CDP indisponible)", it: 'Impossibile applicare il criterio di download (CDP non disponibile)',
    ja: 'ダウンロード ポリシーを適用できません (CDP を利用できません)', ko: '다운로드 정책을 적용할 수 없습니다 (CDP를 사용할 수 없음)',
    pt: 'Não é possível aplicar a política de downloads (CDP indisponível)', ru: 'Не удаётся применить политику загрузок (CDP недоступен)',
    tr: 'İndirme ilkesi uygulanamıyor (CDP kullanılamıyor)', zh: '无法应用下载策略 (CDP 不可用)',
  },
  'rbi.foreignOrigin': {
    ar: 'صفحة تسجيل الدخول خارج نطاق الإدخال', de: 'Anmeldeseite außerhalb der Domain des Eintrags',
    en: "Login page outside the entry's domain", es: 'Página de inicio de sesión fuera del dominio de la entrada',
    fr: "Page de connexion hors du domaine de l'entrée", it: 'Pagina di accesso fuori dal dominio della voce',
    ja: 'ログインページがエントリのドメイン外にあります', ko: '로그인 페이지가 항목의 도메인 밖에 있습니다',
    pt: 'Página de login fora do domínio da entrada', ru: 'Страница входа вне домена записи',
    tr: 'Giriş sayfası kaydın alan adının dışında', zh: '登录页面不在该条目的域名内',
  },
  'rbi.jsNotDisabled': {
    ar: 'تم رفض الإدخال: يتعذّر تعطيل JavaScript في إطار تسجيل الدخول',
    de: 'Eingabe abgelehnt: JavaScript des Anmelde-Frames kann nicht deaktiviert werden',
    en: 'Input refused: JavaScript of the login frame cannot be disabled',
    es: 'Introducción rechazada: no se puede desactivar el JavaScript del marco de inicio de sesión',
    fr: 'Saisie refusée : JavaScript de la frame de connexion non désactivable',
    it: 'Inserimento rifiutato: impossibile disattivare il JavaScript del frame di accesso',
    ja: '入力が拒否されました: ログイン フレームの JavaScript を無効にできません',
    ko: '입력이 거부되었습니다: 로그인 프레임의 JavaScript를 비활성화할 수 없습니다',
    pt: 'Preenchimento recusado: não é possível desativar o JavaScript do frame de login',
    ru: 'Ввод отклонён: невозможно отключить JavaScript во фрейме входа',
    tr: "Giriş reddedildi: giriş çerçevesinin JavaScript'i devre dışı bırakılamıyor",
    zh: '已拒绝填写：无法禁用登录框架的 JavaScript',
  },
  'rbi.formNotFound': {
    ar: 'تعذّر العثور على نموذج تسجيل الدخول', de: 'Anmeldeformular nicht gefunden', en: 'Login form not found',
    es: 'No se encontró el formulario de inicio de sesión', fr: 'Formulaire de connexion introuvable',
    it: 'Modulo di accesso non trovato', ja: 'ログイン フォームが見つかりません', ko: '로그인 양식을 찾을 수 없습니다',
    pt: 'Formulário de login não encontrado', ru: 'Форма входа не найдена', tr: 'Giriş formu bulunamadı', zh: '未找到登录表单',
  },
  'rbi.fieldsNotFound': {
    ar: 'تعذّر العثور على حقول تسجيل الدخول في الصفحة', de: 'Anmeldefelder auf der Seite nicht gefunden',
    en: 'Login fields not found on the page', es: 'No se encontraron los campos de inicio de sesión en la página',
    fr: 'Champs de connexion introuvables sur la page', it: 'Campi di accesso non trovati nella pagina',
    ja: 'ページにログイン フィールドが見つかりません', ko: '페이지에서 로그인 필드를 찾을 수 없습니다',
    pt: 'Campos de login não encontrados na página', ru: 'Поля входа на странице не найдены',
    tr: 'Sayfada giriş alanları bulunamadı', zh: '页面上未找到登录字段',
  },
  'rbi.loginNotConfirmed': {
    ar: 'لم يتم تأكيد تسجيل الدخول (انتهت المهلة)', de: 'Anmeldung nicht bestätigt (Zeitüberschreitung)',
    en: 'Login not confirmed (timeout)', es: 'Inicio de sesión no confirmado (tiempo de espera agotado)',
    fr: 'Connexion non confirmée (délai dépassé)', it: 'Accesso non confermato (tempo scaduto)',
    ja: 'ログインが確認されませんでした (タイムアウト)', ko: '로그인이 확인되지 않았습니다 (시간 초과)',
    pt: 'Login não confirmado (tempo esgotado)', ru: 'Вход не подтверждён (истекло время ожидания)',
    tr: 'Giriş onaylanmadı (zaman aşımı)', zh: '登录未确认 (超时)',
  },
  'rbi.loginFailed': {
    ar: 'فشل تسجيل الدخول في الصفحة', de: 'Anmeldung auf der Seite fehlgeschlagen', en: 'Login failed on the page',
    es: 'Error de inicio de sesión en la página', fr: 'Connexion échouée sur la page', it: 'Accesso non riuscito nella pagina',
    ja: 'ページでのログインに失敗しました', ko: '페이지에서 로그인에 실패했습니다', pt: 'Falha no login na página',
    ru: 'Не удалось выполнить вход на странице', tr: 'Sayfada giriş başarısız oldu', zh: '页面登录失败',
  },
  'rbi.globalTimeout': {
    ar: 'انتهت المهلة ({{seconds}} ث) - الصفحة لا تستجيب', de: 'Zeitüberschreitung ({{seconds}} s) - die Seite antwortet nicht',
    en: 'Timeout ({{seconds}}s) - the page is not responding', es: 'Tiempo de espera agotado ({{seconds}} s): la página no responde',
    fr: 'Délai dépassé ({{seconds}}s) - la page ne répond pas', it: 'Tempo scaduto ({{seconds}} s) - la pagina non risponde',
    ja: 'タイムアウト ({{seconds}} 秒) - ページが応答しません', ko: '시간 초과 ({{seconds}}초) - 페이지가 응답하지 않습니다',
    pt: 'Tempo esgotado ({{seconds}} s) - a página não responde', ru: 'Истекло время ожидания ({{seconds}} с) — страница не отвечает',
    tr: 'Zaman aşımı ({{seconds}} sn) - sayfa yanıt vermiyor', zh: '超时 ({{seconds}} 秒) - 页面无响应',
  },
  'rbi.loginError': {
    ar: 'حدث خطأ أثناء تسجيل الدخول', de: 'Fehler bei der Anmeldung', en: 'Error during login',
    es: 'Error durante el inicio de sesión', fr: 'Erreur pendant la connexion', it: "Errore durante l'accesso",
    ja: 'ログイン中にエラーが発生しました', ko: '로그인 중 오류가 발생했습니다', pt: 'Erro durante o login',
    ru: 'Ошибка при входе', tr: 'Giriş sırasında hata', zh: '登录时出错',
  },
  'rbi.networkRestriction': {
    ar: 'تعذّر تفعيل تقييد الشبكة', de: 'Die Netzwerkbeschränkung kann nicht aktiviert werden',
    en: 'Cannot enable the network restriction', es: 'No se puede activar la restricción de red',
    fr: "Impossible d'activer la restriction réseau", it: 'Impossibile attivare la restrizione di rete',
    ja: 'ネットワーク制限を有効にできません', ko: '네트워크 제한을 활성화할 수 없습니다',
    pt: 'Não é possível ativar a restrição de rede', ru: 'Не удаётся включить сетевое ограничение',
    tr: 'Ağ kısıtlaması etkinleştirilemiyor', zh: '无法启用网络限制',
  },
  'rbi.launchError': {
    ar: 'خطأ في تشغيل جلسة RBI', de: 'Fehler beim Starten der RBI-Sitzung', en: 'Error launching the RBI session',
    es: 'Error al iniciar la sesión RBI', fr: 'Erreur lancement session RBI', it: "Errore nell'avvio della sessione RBI",
    ja: 'RBI セッションの起動エラー', ko: 'RBI 세션 시작 오류', pt: 'Erro ao iniciar a sessão RBI',
    ru: 'Ошибка запуска сеанса RBI', tr: 'RBI oturumu başlatılırken hata', zh: '启动 RBI 会话时出错',
  },
  'rbi.chromiumUnavailable': {
    ar: 'Chromium غير متاح', de: 'Chromium nicht verfügbar', en: 'Chromium not available', es: 'Chromium no disponible',
    fr: 'Chromium non disponible', it: 'Chromium non disponibile', ja: 'Chromium を利用できません',
    ko: 'Chromium을 사용할 수 없습니다', pt: 'Chromium indisponível', ru: 'Chromium недоступен',
    tr: 'Chromium kullanılamıyor', zh: 'Chromium 不可用',
  },

  // ----- Serveur de synchronisation de l'extension : port indisponible (main.js, SYNC-30) -----
  'syncPort.title': {
    ar: 'إضافة Chrome غير متصلة', de: 'Chrome-Erweiterung nicht verbunden', en: 'Chrome extension not connected',
    es: 'Extensión de Chrome no conectada', fr: 'Extension Chrome non reliée', it: 'Estensione Chrome non collegata',
    ja: 'Chrome 拡張機能が接続されていません', ko: 'Chrome 확장 프로그램이 연결되지 않음', pt: 'Extensão do Chrome não conectada',
    ru: 'Расширение Chrome не подключено', tr: 'Chrome uzantısı bağlı değil', zh: 'Chrome 扩展未连接',
  },
  'syncPort.message': {
    ar: 'تعذّر فتح الاتصال بإضافة Chrome (المنفذ {{port}}): الملء التلقائي في المتصفح غير مرتبط بخزنتك.',
    de: 'Die Verbindung zur Chrome-Erweiterung (Port {{port}}) konnte nicht geöffnet werden: Das automatische Ausfüllen im Browser ist nicht mit Ihrem Tresor verbunden.',
    en: 'The link with the Chrome extension (port {{port}}) could not be opened: browser autofill is not connected to your vault.',
    es: 'No se pudo abrir el enlace con la extensión de Chrome (puerto {{port}}): el autocompletado del navegador no está conectado a su bóveda.',
    fr: "Le lien avec l'extension Chrome (port {{port}}) n'a pas pu être ouvert : l'autoremplissage du navigateur n'est pas relié à votre coffre.",
    it: "Impossibile aprire il collegamento con l'estensione Chrome (porta {{port}}): la compilazione automatica del browser non è collegata al tuo vault.",
    ja: 'Chrome 拡張機能との接続 (ポート {{port}}) を開けませんでした。ブラウザーの自動入力はあなたの Vault に接続されていません。',
    ko: 'Chrome 확장 프로그램과의 연결(포트 {{port}})을 열 수 없습니다. 브라우저 자동 완성이 사용자의 Vault에 연결되어 있지 않습니다.',
    pt: 'Não foi possível abrir a ligação com a extensão do Chrome (porta {{port}}): o preenchimento automático do navegador não está conectado ao seu cofre.',
    ru: 'Не удалось открыть связь с расширением Chrome (порт {{port}}): автозаполнение в браузере не связано с вашим хранилищем.',
    tr: 'Chrome uzantısıyla bağlantı (bağlantı noktası {{port}}) açılamadı: tarayıcıdaki otomatik doldurma kasanıza bağlı değil.',
    zh: '无法打开与 Chrome 扩展的连接 (端口 {{port}})：浏览器自动填充未连接到您的保险库。',
  },
  'syncPort.detail': {
    ar: 'المنفذ {{port}} قيد الاستخدام أو محجوز بالفعل، على سبيل المثال بواسطة RDVAULT مفتوح في جلسة Windows أخرى على هذا الجهاز (سطح المكتب البعيد، التبديل السريع بين المستخدمين) أو بواسطة برنامج آخر. وقد تتصل إضافة هذا المتصفح حينئذٍ بذلك التطبيق الآخر بدلًا من تطبيقك. أغلقه، ثم أعد تشغيل RDVAULT.\n\nالرمز: {{code}}',
    de: 'Port {{port}} wird bereits verwendet oder ist reserviert, zum Beispiel durch RDVAULT in einer anderen Windows-Sitzung auf diesem Computer (Remotedesktop, schneller Benutzerwechsel) oder durch ein anderes Programm. Die Erweiterung dieses Browsers könnte dann diese andere Anwendung statt Ihrer erreichen. Schließen Sie sie und starten Sie RDVAULT neu.\n\nCode: {{code}}',
    en: "Port {{port}} is already in use or reserved, for example by RDVAULT open in another Windows session on this computer (remote desktop, fast user switching) or by another program. This browser's extension could then reach that other application instead of yours. Close it, then restart RDVAULT.\n\nCode: {{code}}",
    es: 'El puerto {{port}} ya está en uso o reservado, por ejemplo por RDVAULT abierto en otra sesión de Windows de este equipo (escritorio remoto, cambio rápido de usuario) o por otro programa. La extensión de este navegador podría entonces conectarse a esa otra aplicación en lugar de la suya. Ciérrela y reinicie RDVAULT.\n\nCódigo: {{code}}',
    fr: "Le port {{port}} est déjà utilisé ou réservé, par exemple par RDVAULT ouvert dans une autre session Windows de ce poste (bureau à distance, changement rapide d'utilisateur) ou par un autre programme. L'extension de ce navigateur pourrait alors joindre cette autre application au lieu de la vôtre. Fermez-la, puis redémarrez RDVAULT.\n\nCode : {{code}}",
    it: "La porta {{port}} è già in uso o riservata, ad esempio da RDVAULT aperto in un'altra sessione Windows di questo computer (desktop remoto, cambio rapido utente) o da un altro programma. L'estensione di questo browser potrebbe quindi raggiungere quell'altra applicazione invece della tua. Chiudila, quindi riavvia RDVAULT.\n\nCodice: {{code}}",
    ja: 'ポート {{port}} は既に使用中か予約されています。たとえば、このコンピューターの別の Windows セッション (リモート デスクトップ、ユーザーの簡易切り替え) で開かれている RDVAULT や、別のプログラムが使用している可能性があります。その場合、このブラウザーの拡張機能はあなたのアプリではなく、その別のアプリケーションに接続する可能性があります。そのアプリケーションを閉じてから RDVAULT を再起動してください。\n\nコード: {{code}}',
    ko: '포트 {{port}}이(가) 이미 사용 중이거나 예약되어 있습니다. 예를 들어 이 컴퓨터의 다른 Windows 세션(원격 데스크톱, 빠른 사용자 전환)에서 열린 RDVAULT나 다른 프로그램이 사용 중일 수 있습니다. 이 경우 이 브라우저의 확장 프로그램이 사용자의 앱 대신 다른 애플리케이션에 연결될 수 있습니다. 해당 애플리케이션을 닫은 후 RDVAULT를 다시 시작하세요.\n\n코드: {{code}}',
    pt: 'A porta {{port}} já está em uso ou reservada, por exemplo pelo RDVAULT aberto em outra sessão do Windows neste computador (área de trabalho remota, troca rápida de usuário) ou por outro programa. A extensão deste navegador poderia então acessar esse outro aplicativo em vez do seu. Feche-o e reinicie o RDVAULT.\n\nCódigo: {{code}}',
    ru: 'Порт {{port}} уже используется или зарезервирован, например RDVAULT, открытым в другом сеансе Windows на этом компьютере (удалённый рабочий стол, быстрое переключение пользователей), или другой программой. Тогда расширение этого браузера может обращаться к этому другому приложению вместо вашего. Закройте его и перезапустите RDVAULT.\n\nКод: {{code}}',
    tr: "{{port}} numaralı bağlantı noktası zaten kullanımda veya ayrılmış; örneğin bu bilgisayardaki başka bir Windows oturumunda açık olan RDVAULT (uzak masaüstü, hızlı kullanıcı değiştirme) veya başka bir program tarafından. Bu durumda bu tarayıcının uzantısı sizinki yerine o diğer uygulamaya bağlanabilir. Onu kapatın, ardından RDVAULT'u yeniden başlatın.\n\nKod: {{code}}",
    zh: '端口 {{port}} 已被占用或保留，例如被此计算机上另一个 Windows 会话 (远程桌面、快速用户切换) 中打开的 RDVAULT 或其他程序占用。此时，此浏览器的扩展可能会连接到该应用程序而不是您的应用程序。请将其关闭，然后重新启动 RDVAULT。\n\n代码：{{code}}',
  },
};

// Langue communiquée par l'interface (null tant que le renderer ne l'a pas signalée)
let uiLang = null;

// Fournisseur de la langue par défaut : LANG de config.cfg (configLoader, chargé à la demande pour que ce
// module reste utilisable sans Electron). Remplaçable par setDefaultLanguageProvider (tests).
let defaultLanguageProvider = () => require('./configLoader').getConfig().LANG;

/**
 * Normalise un code de langue (« fr », « FR », « pt-BR », « zh_CN ») vers l'un des 12 codes pris en
 * charge, ou null s'il n'est pas reconnu (valeur non textuelle, trop longue, langue inconnue).
 * @param {*} value
 * @returns {string|null}
 */
function normalizeLang(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16) return null;
  const primary = value.trim().toLowerCase().split(/[-_]/)[0];
  return SUPPORTED_LANGS.includes(primary) ? primary : null;
}

/**
 * Enregistre la langue courante de l'interface (IPC 'set-ui-language', expéditeur validé par main.js).
 * Une valeur inconnue est ignorée : la langue précédente est conservée.
 * @returns {boolean} true si la langue a été acceptée
 */
function setUiLanguage(value) {
  const lang = normalizeLang(value);
  if (!lang) return false;
  uiLang = lang;
  return true;
}

/** Remplace le fournisseur de la langue par défaut (tests) ; null rétablit LANG de config.cfg */
function setDefaultLanguageProvider(fn) {
  defaultLanguageProvider = typeof fn === 'function' ? fn : () => require('./configLoader').getConfig().LANG;
}

/** Oublie la langue signalée par l'interface (tests) */
function resetUiLanguage() {
  uiLang = null;
}

/** Langue effective : interface, sinon LANG de config.cfg, sinon anglais */
function getLanguage() {
  if (uiLang) return uiLang;
  try {
    return normalizeLang(defaultLanguageProvider()) || FALLBACK_LANG;
  } catch {
    return FALLBACK_LANG;
  }
}

/**
 * Traduit une clé du processus principal. Variables « {{nom}} » remplacées par String(vars.nom).
 * Repli : anglais si la langue n'a pas la clé ; la clé elle-même si elle est inconnue.
 * @param {string} key
 * @param {Object} [vars]
 * @param {string} [lang] - langue imposée (sinon getLanguage())
 * @returns {string}
 */
function tm(key, vars = {}, lang) {
  const entry = MESSAGES[key];
  if (!entry) return key;
  const code = normalizeLang(lang) || getLanguage();
  const template = entry[code] || entry[FALLBACK_LANG];
  return template.replace(/\{\{(\w+)\}\}/g, (match, name) =>
    (vars && Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match));
}

module.exports = {
  SUPPORTED_LANGS,
  MESSAGES,
  normalizeLang,
  setUiLanguage,
  resetUiLanguage,
  setDefaultLanguageProvider,
  getLanguage,
  tm,
};
