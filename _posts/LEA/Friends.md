# 友情链接😅😅😅

<style>
.friends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 20px;
  margin: 30px 0;
}

.friend-card {
  display: block;
  text-decoration: none;
  color: inherit;
  background: var(--card-bg);
  border-radius: 12px;
  padding: 15px;
  text-align: center;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  box-shadow: 0 2px 12px rgba(0,0,0,0.08);
  border: 1px solid var(--border-color);
}

.friend-card:hover {
  transform: scale(1.02);
  box-shadow: 0 6px 16px rgba(0,0,0,0.15);
  text-decoration: none;
  color: inherit;
}

.friend-avatar {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  object-fit: cover;
  margin: 0 auto 10px;
  border: 3px solid var(--accent-color);
}

.friend-name {
  font-weight: 600;
  font-size: 14px;
  margin: 0;
  color: var(--text-color);
}

.friend-category {
  margin-top: 40px;
  font-size: 20px;
  font-weight: 600;
  color: var(--accent-color);
  border-bottom: 2px solid var(--accent-color);
  padding-bottom: 8px;
  margin-bottom: 20px;
}

@media (max-width: 768px) {
  .friends-grid {
    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
    gap: 15px;
  }
  
  .friend-card {
    padding: 12px;
  }
  
  .friend-avatar {
    width: 60px;
    height: 60px;
  }
}
</style>

<div class="friends-grid">

  <a href="https://baozongwi.xyz/" class="friend-card" target="_blank">
    <img src="http://q1.qlogo.cn/g?b=qq&nk=2405758945&s=100" alt="同学B" class="friend-avatar">
    <div class="friend-name">baozongwi</div>
  </a>

  <a href="https://blog.shangwendada.top/" class="friend-card" target="_blank">
    <img src="http://q1.qlogo.cn/g?b=qq&nk=2277873568&s=100" alt="" class="friend-avatar">
    <div class="friend-name">SWDD</div>
  </a>

  <a href="https://y7syeu.github.io/#傻逼司马柿子" class="friend-card" target="_blank">
    <img src="https://y7syeu.github.io/images/avatar.jpg" alt="" class="friend-avatar">
    <div class="friend-name">y7syeu</div>
  </a>

  <a href="https://blogyoulin.top/" class="friend-card" target="_blank">
    <img src="http://q1.qlogo.cn/g?b=qq&nk=1498041059&s=100" alt="同学B" class="friend-avatar">
    <div class="friend-name">幽林</div>
  </a>

  <a href="https://github.com/IHK-ONE" class="friend-card" target="_blank">
    <img src="http://q1.qlogo.cn/g?b=qq&nk=813888284&s=100" alt="同学B" class="friend-avatar">
    <div class="friend-name">黄康</div>
  </a>

  
  
</div>
