import Vue from 'vue';
import Router from 'vue-router';

Vue.use(Router);

export default new Router({
  routes: [
    { path: '/catalog', component: Catalog },
    { path: '/cart', component: Cart }
  ]
});
