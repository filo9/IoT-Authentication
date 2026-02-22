import { createApp } from 'vue'
import App from './App.vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css' // 引入暗黑模式变量
import '@element-plus/icons-vue'

const app = createApp(App)

// 全局注册 Element Plus
app.use(ElementPlus)

app.mount('#app')