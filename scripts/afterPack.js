const path = require('path');
const { execSync } = require('child_process');

exports.default = async function(context) {
  // Chemin vers l'exécutable
  const exePath = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.exe`);

  // Chemin vers l'icône
  const iconPath = path.join(context.packager.projectDir, 'assets', 'icon.ico');

  // Chemin vers rcedit
  const rceditPath = path.join(context.packager.projectDir, 'node_modules', 'rcedit', 'bin', 'rcedit-x64.exe');

  console.log(`Setting icon on ${exePath}`);

  try {
    execSync(`"${rceditPath}" "${exePath}" --set-icon "${iconPath}"`, { stdio: 'inherit' });
    console.log('Icon set successfully!');
  } catch (error) {
    console.error('Failed to set icon:', error.message);
  }
};
