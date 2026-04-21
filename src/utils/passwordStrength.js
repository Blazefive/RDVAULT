// src/utils/passwordStrength.js

/**
 * Calcule l'entropie d'un mot de passe en bits
 * @param {string} password - Le mot de passe à analyser
 * @returns {number} L'entropie en bits
 */
export const calculateEntropy = (password) => {
  if (!password) return 0;

  let poolSize = 0;

  // Détecter les types de caractères utilisés
  const hasLowerCase = /[a-z]/.test(password);
  const hasUpperCase = /[A-Z]/.test(password);
  const hasDigits = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%&*+=?^~,]/.test(password);
  const hasBrackets = /[\[\]{}()<>]/.test(password);
  const hasMinus = /-/.test(password);
  const hasUnderline = /_/.test(password);
  // Latin-1 et caractères étendus
  const hasLatin1 = /[À-ÿ]/.test(password);

  if (hasLowerCase) poolSize += 26;
  if (hasUpperCase) poolSize += 26;
  if (hasDigits) poolSize += 10;
  if (hasSpecial) poolSize += 14; // ! @ # $ % & * + = ? ^ ~ ,
  if (hasBrackets) poolSize += 8; // [ ] { } ( ) < >
  if (hasMinus) poolSize += 1;
  if (hasUnderline) poolSize += 1;
  if (hasLatin1) poolSize += 128;

  if (poolSize === 0) return 0;
  return Math.floor(password.length * Math.log2(poolSize));
};

/**
 * Évalue la force d'un mot de passe basé sur son entropie
 * @param {number} entropy - L'entropie en bits
 * @returns {{ strength: string, color: string, percentage: number }}
 */
export const getPasswordStrength = (entropy) => {
  let strength, color, percentage;

  if (entropy < 50) {
    strength = 'Faible';
    color = 'var(--error)';
    percentage = Math.min(100, (entropy / 50) * 25);
  } else if (entropy < 70) {
    strength = 'Moyenne';
    color = 'var(--warning)';
    percentage = 25 + ((entropy - 50) / 20) * 25;
  } else if (entropy < 90) {
    strength = 'Forte';
    color = 'var(--success)';
    percentage = 50 + ((entropy - 70) / 20) * 25;
  } else {
    strength = 'Très forte';
    color = 'var(--info)';
    percentage = Math.min(100, 75 + ((entropy - 90) / 30) * 25);
  }

  return { strength, color, percentage };
};

/**
 * Analyse complète de la force d'un mot de passe
 * @param {string} password - Le mot de passe à analyser
 * @returns {{ entropy: number, strength: string, color: string, percentage: number }}
 */
export const analyzePassword = (password) => {
  const entropy = calculateEntropy(password);
  const { strength, color, percentage } = getPasswordStrength(entropy);
  return { entropy, strength, color, percentage };
};
