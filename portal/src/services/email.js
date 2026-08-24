const nodemailer = require('nodemailer');

// Crear transportador SMTP de forma perezosa al enviar
function getTransporter() {
  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || '587');
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const secure = process.env.SMTP_SECURE === 'true'; // true para puerto 465, false para otros

  if (!host) {
    console.warn('[EMAIL] SMTP_HOST no configurado en las variables de entorno. Los correos no se enviarán.');
    return null;
  }

  const transportConfig = {
    host,
    port,
    secure,
    tls: {
      rejectUnauthorized: false // Permite certificados autofirmados institucionales si aplica
    }
  };

  // Si se configuran tanto el usuario como la contraseña, agregar autenticación
  if (user && pass) {
    transportConfig.auth = {
      user,
      pass
    };
  }

  return nodemailer.createTransport(transportConfig);
}

/**
 * Envía un correo con el enlace para restablecer la contraseña.
 */
async function sendResetPasswordEmail({ to, nombres, token }) {
  const transporter = getTransporter();
  if (!transporter) {
    throw new Error('El servicio de correo institucional no está configurado.');
  }

  const defaultFrom = process.env.SMTP_USER || 'no-reply@pastaza.gob.ec';
  const from = process.env.SMTP_FROM || `"Portal Administrativo Pastaza" <${defaultFrom}>`;
  
  // URL base del portal (usar variables de entorno o fallback a localhost)
  const baseUrl = process.env.PORTAL_ADMIN_URL || 'https://omada.pastaza.gob.ec/admin';
  const resetLink = `${baseUrl}/reset-password.html?token=${token}`;

  const mailOptions = {
    from,
    to,
    subject: 'Restablecimiento de Contraseña - Portal Wi-Fi Pastaza',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #f0f0f0; border-radius: 8px;">
        <h2 style="color: #1e3a8a; text-align: center;">Portal Administrativo Pastaza</h2>
        <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p>Estimado/a <strong>${nombres}</strong>,</p>
        <p>Hemos recibido una solicitud para restablecer la contraseña de su cuenta de administración del portal cautivo.</p>
        <p>Para proceder, haga clic en el siguiente botón. Este enlace es válido por <strong>15 minutos</strong>:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetLink}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Restablecer Contraseña</a>
        </div>
        <p style="color: #6b7280; font-size: 13px;">Si el botón no funciona, copie y pegue la siguiente URL en su navegador:</p>
        <p style="color: #2563eb; font-size: 13px; word-break: break-all;"><a href="${resetLink}">${resetLink}</a></p>
        <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p style="font-size: 12px; color: #9ca3af; text-align: center;">Si usted no solicitó este cambio, puede ignorar este correo de forma segura. Su contraseña actual permanecerá sin cambios.</p>
      </div>
    `
  };

  const info = await transporter.sendMail(mailOptions);
  console.log(`[EMAIL] Correo de restablecimiento enviado a ${to}. MessageId: ${info.messageId}`);
  return info;
}

module.exports = {
  sendResetPasswordEmail
};
