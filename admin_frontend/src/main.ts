import { createApp } from 'vue'
import App from './App.vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import './styles/tokens.css'
import './styles/base.css'
import './styles/auth.css'
import './styles/layout.css'
import './styles/components.css'
import './styles/overlays.css'
import './styles/toast.css'
import './styles/utilities.css'
import './styles/responsive.css'

createApp(App)
  .use(ElementPlus)
  .mount('#app')
