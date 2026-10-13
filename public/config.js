// Public settings for the browser. The publishable key is meant to be public:
// row-level security means it can't read or change any demo table.
window.DEMO_CONFIG = {
  supabaseUrl: 'https://floagxzbvqxrscnqotyn.supabase.co',
  supabaseKey: 'sb_publishable_lr9W5YIsQqrGJzpuRUX9bA_EuRbEcci',
  emailSignIn: true, // needs the custom SMTP sender set up in Supabase
  adminUrl: 'https://api-error-explainer.caseyledbetter.com/admin',
};
