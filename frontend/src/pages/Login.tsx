import React from 'react';
import { Link, useNavigate } from 'react-router-dom';

export default function Login() {
  const navigate = useNavigate();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // Navigate to dashboard on successful login simulation
    navigate('/dashboard');
  };

  return (
    <div className="login-page">
      <div className="login-bg-effect"></div>
      
      <div className="login-container">
        <div className="login-logo-container">
          <img 
            alt="Sentinel Security Platform Logo" 
            className="login-logo" 
            src="https://lh3.googleusercontent.com/aida/AP1WRLuwerRDvsobOivIzvDdFN-sM1KgDiEZ6mYfN72dgWjbgZmLTSehFOk3Mig4sauj8U0qb7htzCYIdLlHgpE0RD69kJyyVOG9TTa38FuWh7pbNPMBo-G5Hv1NFDM0IgTzVTAIe7gPKwr5wdhjY4QKu7hDZW4YiH1OrySkQxFAehC6PvRyb7PJnOX1oydZ8Vof895l2B2x6TGU5zWgJ8QP4GY9EK_YIITdWY1BLdbDt1VnQbsq7LQKwtfz6IJs"
          />
        </div>
        
        <h1 className="login-title">Sign in to Sentinel</h1>
        
        <div className="login-card">
          <form className="login-form" onSubmit={handleLogin}>
            
            <div className="social-login-group">
              <button className="btn-social" type="button">
                <img 
                  alt="Google" 
                  className="social-icon" 
                  src="https://lh3.googleusercontent.com/aida-public/AB6AXuDuiCDKpNDck2ZiJj8mfqdPU4W0I-YHdas8Qw2lyBplKhcdiWgr9-gFJa_fr1CfH7VirQtIJJ-aSlK4rZSCST6sGgR2et9_YapXKlpAkiNdyGe9uXlAoWciP697YsJAipOzk2zIkrcBZQtNmxNjODgd0eS2ii1qKSSS8x2y2Wzx2-W6Whx4m5NeK4xFDgvXbx4jBZD4omFLTiB-ZS4skseaet_nDS4edRpz_9KjUw2Hsbw81D3ogTDheg"
                />
                <span>Continue with Google</span>
              </button>
              
              <div className="divider-container">
                <div className="divider-line"></div>
                <span className="divider-text">or</span>
                <div className="divider-line"></div>
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="email" className="form-label">Email address</label>
              <input 
                id="email" 
                name="email" 
                type="email" 
                required 
                className="form-input" 
                placeholder="you@example.com"
              />
            </div>
            
            <div className="form-group">
              <div className="form-label-row">
                <label htmlFor="password" className="form-label">Password</label>
                <a href="#" className="forgot-password">Forgot password?</a>
              </div>
              <input 
                id="password" 
                name="password" 
                type="password" 
                required 
                className="form-input" 
              />
            </div>
            
            <button className="btn-submit" type="submit">
              Sign in
              <span className="material-symbols-outlined">login</span>
            </button>
            
          </form>
        </div>
        
        <div className="signup-prompt">
          <p>
            New to Sentinel? 
            <Link to="/login" className="signup-link">Create an account</Link>.
          </p>
        </div>
        
        <div className="login-footer">
          <a href="#">Terms</a>
          <a href="#">Privacy</a>
          <a href="#">Security</a>
          <a href="#" className="contact-link">
            <span className="material-symbols-outlined icon-small">public</span> Contact
          </a>
        </div>
        
      </div>
    </div>
  );
}
