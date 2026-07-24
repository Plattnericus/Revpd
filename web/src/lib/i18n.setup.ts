/*
  Wizard strings, kept apart from the main dictionary so the first-run texts
  can be read side by side across languages rather than hunted for in ten
  separate blocks. They are merged in by i18n.ts.
*/

export const setupDe = {
  'setup.adminTitle': 'Administrator anlegen',
  'setup.adminHint': 'Dieses Konto verwaltet das Gateway. Es lässt sich später nicht ohne Server-Zugriff wiederherstellen.',
  'setup.repeat': 'Passwort wiederholen',
  'setup.passwordShort': 'Mindestens 12 Zeichen',
  'setup.mismatch': 'Die Passwörter stimmen nicht überein',
  'setup.enrollTitle': 'Zweiten Faktor einrichten',
  'setup.confirmCode': 'Code aus der App zur Bestätigung',
  'setup.targetTitle': 'Ersten Rechner eintragen',
  'setup.targetHint': 'Der Windows-PC, den du aus der Ferne erreichen möchtest.',
  'setup.macHint': 'Wird zum Aufwecken gebraucht. Format egal.',
  'setup.later': 'Später eintragen',
  'setup.doneTitle': 'Alles bereit',
  'setup.doneHint': 'Du kannst dich jetzt mit der Remotedesktopverbindung anmelden.',
  'setup.connectWith': 'Verbinden mit',
  'setup.open': 'Zur Übersicht',
} as const

export type SetupKey = keyof typeof setupDe
type SetupDict = Record<SetupKey, string>

export const setupEn: SetupDict = {
  'setup.adminTitle': 'Create an administrator',
  'setup.adminHint': 'This account manages the gateway. It cannot be recovered later without access to the server.',
  'setup.repeat': 'Repeat password',
  'setup.passwordShort': 'At least 12 characters',
  'setup.mismatch': 'The passwords do not match',
  'setup.enrollTitle': 'Set up the second factor',
  'setup.confirmCode': 'Code from the app to confirm',
  'setup.targetTitle': 'Add your first machine',
  'setup.targetHint': 'The Windows PC you want to reach remotely.',
  'setup.macHint': 'Needed to wake it. Any format works.',
  'setup.later': 'Add one later',
  'setup.doneTitle': 'All set',
  'setup.doneHint': 'You can sign in from Remote Desktop now.',
  'setup.connectWith': 'Connect to',
  'setup.open': 'Open the overview',
}

export const setupFr: SetupDict = {
  'setup.adminTitle': 'Créer un administrateur',
  'setup.adminHint': 'Ce compte administre la passerelle. Il ne pourra pas être récupéré sans accès au serveur.',
  'setup.repeat': 'Répéter le mot de passe',
  'setup.passwordShort': 'Au moins 12 caractères',
  'setup.mismatch': 'Les mots de passe ne correspondent pas',
  'setup.enrollTitle': 'Configurer le second facteur',
  'setup.confirmCode': 'Code de l’application pour confirmer',
  'setup.targetTitle': 'Ajouter votre première machine',
  'setup.targetHint': 'Le PC Windows que vous souhaitez atteindre à distance.',
  'setup.macHint': 'Nécessaire pour le réveiller. Tout format convient.',
  'setup.later': 'Ajouter plus tard',
  'setup.doneTitle': 'Tout est prêt',
  'setup.doneHint': 'Vous pouvez maintenant vous connecter depuis Bureau à distance.',
  'setup.connectWith': 'Se connecter à',
  'setup.open': 'Ouvrir la vue d’ensemble',
}

export const setupEs: SetupDict = {
  'setup.adminTitle': 'Crear un administrador',
  'setup.adminHint': 'Esta cuenta administra la puerta de enlace. No podrá recuperarse sin acceso al servidor.',
  'setup.repeat': 'Repetir contraseña',
  'setup.passwordShort': 'Al menos 12 caracteres',
  'setup.mismatch': 'Las contraseñas no coinciden',
  'setup.enrollTitle': 'Configurar el segundo factor',
  'setup.confirmCode': 'Código de la aplicación para confirmar',
  'setup.targetTitle': 'Añade tu primer equipo',
  'setup.targetHint': 'El PC con Windows al que quieres acceder de forma remota.',
  'setup.macHint': 'Necesaria para encenderlo. Cualquier formato vale.',
  'setup.later': 'Añadir más tarde',
  'setup.doneTitle': 'Todo listo',
  'setup.doneHint': 'Ya puedes conectarte desde Escritorio remoto.',
  'setup.connectWith': 'Conectar a',
  'setup.open': 'Abrir el resumen',
}

export const setupIt: SetupDict = {
  'setup.adminTitle': 'Crea un amministratore',
  'setup.adminHint': 'Questo account gestisce il gateway. Non potrà essere recuperato senza accesso al server.',
  'setup.repeat': 'Ripeti la password',
  'setup.passwordShort': 'Almeno 12 caratteri',
  'setup.mismatch': 'Le password non coincidono',
  'setup.enrollTitle': 'Configura il secondo fattore',
  'setup.confirmCode': 'Codice dall’app per confermare',
  'setup.targetTitle': 'Aggiungi il primo computer',
  'setup.targetHint': 'Il PC Windows che vuoi raggiungere da remoto.',
  'setup.macHint': 'Serve per accenderlo. Va bene qualsiasi formato.',
  'setup.later': 'Aggiungi più tardi',
  'setup.doneTitle': 'Tutto pronto',
  'setup.doneHint': 'Ora puoi accedere da Connessione desktop remoto.',
  'setup.connectWith': 'Connettiti a',
  'setup.open': 'Apri la panoramica',
}

export const setupNl: SetupDict = {
  'setup.adminTitle': 'Beheerder aanmaken',
  'setup.adminHint': 'Dit account beheert de gateway. Het is later niet te herstellen zonder toegang tot de server.',
  'setup.repeat': 'Wachtwoord herhalen',
  'setup.passwordShort': 'Minstens 12 tekens',
  'setup.mismatch': 'De wachtwoorden komen niet overeen',
  'setup.enrollTitle': 'Tweede factor instellen',
  'setup.confirmCode': 'Code uit de app ter bevestiging',
  'setup.targetTitle': 'Voeg je eerste computer toe',
  'setup.targetHint': 'De Windows-pc die je op afstand wilt bereiken.',
  'setup.macHint': 'Nodig om hem aan te zetten. Elk formaat werkt.',
  'setup.later': 'Later toevoegen',
  'setup.doneTitle': 'Klaar',
  'setup.doneHint': 'Je kunt nu inloggen via Extern bureaublad.',
  'setup.connectWith': 'Verbinden met',
  'setup.open': 'Overzicht openen',
}

export const setupPl: SetupDict = {
  'setup.adminTitle': 'Utwórz administratora',
  'setup.adminHint': 'To konto zarządza bramą. Bez dostępu do serwera nie da się go później odzyskać.',
  'setup.repeat': 'Powtórz hasło',
  'setup.passwordShort': 'Co najmniej 12 znaków',
  'setup.mismatch': 'Hasła nie są zgodne',
  'setup.enrollTitle': 'Skonfiguruj drugi składnik',
  'setup.confirmCode': 'Kod z aplikacji, aby potwierdzić',
  'setup.targetTitle': 'Dodaj pierwszy komputer',
  'setup.targetHint': 'Komputer z systemem Windows, do którego chcesz mieć zdalny dostęp.',
  'setup.macHint': 'Potrzebny do włączenia. Dowolny format.',
  'setup.later': 'Dodaj później',
  'setup.doneTitle': 'Gotowe',
  'setup.doneHint': 'Możesz się teraz zalogować przez Pulpit zdalny.',
  'setup.connectWith': 'Połącz z',
  'setup.open': 'Otwórz przegląd',
}

export const setupPt: SetupDict = {
  'setup.adminTitle': 'Criar um administrador',
  'setup.adminHint': 'Esta conta administra o gateway. Não poderá ser recuperada sem acesso ao servidor.',
  'setup.repeat': 'Repetir palavra-passe',
  'setup.passwordShort': 'Pelo menos 12 caracteres',
  'setup.mismatch': 'As palavras-passe não coincidem',
  'setup.enrollTitle': 'Configurar o segundo fator',
  'setup.confirmCode': 'Código da aplicação para confirmar',
  'setup.targetTitle': 'Adicione o primeiro computador',
  'setup.targetHint': 'O PC com Windows a que quer aceder remotamente.',
  'setup.macHint': 'Necessário para o ligar. Qualquer formato serve.',
  'setup.later': 'Adicionar mais tarde',
  'setup.doneTitle': 'Tudo pronto',
  'setup.doneHint': 'Já pode entrar pelo Ambiente de trabalho remoto.',
  'setup.connectWith': 'Ligar a',
  'setup.open': 'Abrir a visão geral',
}

export const setupTr: SetupDict = {
  'setup.adminTitle': 'Yönetici oluştur',
  'setup.adminHint': 'Bu hesap ağ geçidini yönetir. Sunucuya erişim olmadan sonradan kurtarılamaz.',
  'setup.repeat': 'Parolayı tekrarla',
  'setup.passwordShort': 'En az 12 karakter',
  'setup.mismatch': 'Parolalar eşleşmiyor',
  'setup.enrollTitle': 'İkinci faktörü ayarla',
  'setup.confirmCode': 'Onaylamak için uygulamadaki kod',
  'setup.targetTitle': 'İlk bilgisayarınızı ekleyin',
  'setup.targetHint': 'Uzaktan erişmek istediğiniz Windows bilgisayarı.',
  'setup.macHint': 'Başlatmak için gerekli. Her biçim olur.',
  'setup.later': 'Sonra ekle',
  'setup.doneTitle': 'Hazır',
  'setup.doneHint': 'Artık Uzak Masaüstü ile giriş yapabilirsiniz.',
  'setup.connectWith': 'Şuraya bağlan',
  'setup.open': 'Genel bakışı aç',
}

export const setupRu: SetupDict = {
  'setup.adminTitle': 'Создать администратора',
  'setup.adminHint': 'Эта учётная запись управляет шлюзом. Восстановить её без доступа к серверу не получится.',
  'setup.repeat': 'Повторите пароль',
  'setup.passwordShort': 'Не менее 12 символов',
  'setup.mismatch': 'Пароли не совпадают',
  'setup.enrollTitle': 'Настроить второй фактор',
  'setup.confirmCode': 'Код из приложения для подтверждения',
  'setup.targetTitle': 'Добавьте первый компьютер',
  'setup.targetHint': 'Компьютер с Windows, к которому нужен удалённый доступ.',
  'setup.macHint': 'Нужен для включения. Формат любой.',
  'setup.later': 'Добавить позже',
  'setup.doneTitle': 'Всё готово',
  'setup.doneHint': 'Теперь можно входить через удалённый рабочий стол.',
  'setup.connectWith': 'Подключиться к',
  'setup.open': 'Открыть обзор',
}
