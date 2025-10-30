require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const mongoURI = process.env.MONGODB_URI;

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role: { type: String, required: true },
  status: { type: String, default: 'active' },
  linked_influencer: mongoose.Schema.Types.ObjectId,
  last_login: Date,
  force_password_reset: Boolean
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

async function createAdmin() {
  try {
    await mongoose.connect(mongoURI);
    console.log('✅ Connected to MongoDB Atlas\n');

    const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'ChangeMe123!';

    console.log('Creating admin with:');
    console.log('  Email:', adminEmail);
    console.log('  Password:', adminPassword);
    console.log('');

    // Check if admin exists
    const existingAdmin = await User.findOne({ email: adminEmail.toLowerCase() });

    if (existingAdmin) {
      console.log('⚠️  Admin already exists. Updating password...\n');

      const passwordHash = await bcrypt.hash(adminPassword, 12);
      existingAdmin.password_hash = passwordHash;
      existingAdmin.role = 'admin';
      existingAdmin.status = 'active';
      await existingAdmin.save();

      console.log('✅ Admin password updated!');
    } else {
      console.log('Creating new admin user...\n');

      const passwordHash = await bcrypt.hash(adminPassword, 12);

      const admin = await User.create({
        email: adminEmail.toLowerCase(),
        password_hash: passwordHash,
        role: 'admin',
        status: 'active',
        force_password_reset: false
      });

      console.log('✅ Admin user created!');
      console.log('   ID:', admin._id);
    }

    console.log('\n📝 Admin Login Credentials:');
    console.log('   URL: http://localhost:3002/admin');
    console.log('   Email:', adminEmail);
    console.log('   Password:', adminPassword);
    console.log('');

    process.exit(0);
  } catch (error) {
    console.error('\n❌ Error:', error.message);
    process.exit(1);
  }
}

createAdmin();
