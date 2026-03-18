import React, { useState, useEffect } from 'react';
import { Shield, ChevronRight, ChevronLeft, ArrowRight, User, Search, Instagram } from 'lucide-react';

// --- MARKDOWN PARSER ---
const parseInline = (text) => {
  if (!text) return null;
  const parts = text.split(/(!\[[^\]]*\]\([^)]+\)|`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\))/g);
  
  return parts.map((part, index) => {
    if (!part) return null;
    
    const imgMatch = part.match(/^!\[([^\]]*)\]\(([^)]+)\)$/);
    if (imgMatch) {
      return (
        <span key={index} className="block my-6 text-center">
          <img src={imgMatch[2]} alt={imgMatch[1]} className="rounded-xl shadow-md max-w-full border border-slate-200 inline-block" />
          {imgMatch[1] && <span className="block text-sm text-[#0b2636]/50 mt-2 font-medium">{imgMatch[1]}</span>}
        </span>
      );
    }
    
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={index} className="px-1.5 py-0.5 rounded bg-[#cbd6dc]/50 text-[#d63384] font-mono text-xs sm:text-sm break-words">{part.slice(1, -1)}</code>;
    }
    
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={index} className="font-black text-[#0b2636]">{part.slice(2, -2)}</strong>;
    }
    
    const linkMatch = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (linkMatch) {
      return <a key={index} href={linkMatch[2]} target="_blank" rel="noopener noreferrer" className="text-[#3c8ebd] hover:underline font-bold transition-all break-words">{linkMatch[1]}</a>;
    }
    
    return <span key={index}>{part}</span>;
  });
};

const parseMarkdown = (mdString) => {
  if (!mdString) return null;
  
  let content = mdString.trim();
  if (content.startsWith('---')) {
    const endIdx = content.indexOf('---', 3);
    if (endIdx !== -1) {
      content = content.substring(endIdx + 3).trim();
    }
  }

  const lines = content.split(/\r?\n/);
  const elements = [];
  let inCodeBlock = false;
  let codeContent = [];
  let codeLang = '';
  let listItems = [];

  const flushList = () => {
    if (listItems.length > 0) {
      elements.push(<ul key={`ul-${elements.length}`} className="list-disc ml-6 sm:ml-8 mb-8 space-y-2 text-[#0b2636]/80 text-base sm:text-lg leading-relaxed">{listItems}</ul>);
      listItems = [];
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith('```')) {
      flushList();
      if (inCodeBlock) {
        elements.push(
          <div key={`code-${i}`} className="my-6 sm:my-8 rounded-xl bg-[#0b1820] border border-[#cbd6dc]/30 overflow-hidden shadow-xl w-full">
            {codeLang && <div className="px-4 py-2 bg-[#051017] text-xs text-white/50 font-mono border-b border-white/10 uppercase tracking-widest">{codeLang}</div>}
            <pre className="p-4 sm:p-6 overflow-x-auto text-xs sm:text-sm font-mono text-white/90 leading-relaxed max-w-[85vw] md:max-w-none">
              <code>{codeContent.join('\n')}</code>
            </pre>
          </div>
        );
        inCodeBlock = false;
        codeContent = [];
      } else {
        inCodeBlock = true;
        codeLang = line.replace('```', '').trim();
      }
      continue;
    }

    if (inCodeBlock) {
      codeContent.push(line);
      continue;
    }

    if (line.trim() === '---' || line.trim() === '***' || line.trim() === '___') {
      flushList();
      elements.push(<hr key={i} className="my-8 sm:my-10 border-t-2 border-[#0b2636]/10" />);
      continue;
    }

    if (line.match(/^#{1,6}\s/)) {
      flushList();
      const level = line.match(/^(#{1,6})/)[0].length;
      const text = line.replace(/^#{1,6}\s+/, '');
      if (level === 1) elements.push(<h1 key={i} className="text-3xl sm:text-4xl md:text-5xl font-black mt-12 sm:mt-16 mb-6 sm:mb-8 text-[#0b2636] tracking-tighter leading-tight">{parseInline(text)}</h1>);
      else if (level === 2) elements.push(<h2 key={i} className="text-2xl sm:text-3xl md:text-4xl font-bold mt-10 sm:mt-12 mb-4 sm:mb-6 text-[#0b2636] tracking-tight border-b-2 border-[#3c8ebd]/20 pb-3 leading-tight">{parseInline(text)}</h2>);
      else if (level === 3) elements.push(<h3 key={i} className="text-xl sm:text-2xl font-bold mt-8 sm:mt-10 mb-4 text-[#0b2636] tracking-tight leading-tight">{parseInline(text)}</h3>);
      else elements.push(<h4 key={i} className="text-lg sm:text-xl font-bold mt-6 sm:mt-8 mb-3 sm:mb-4 text-[#0b2636] leading-tight">{parseInline(text)}</h4>);
    } 
    else if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      listItems.push(<li key={i}>{parseInline(line.trim().substring(2))}</li>);
    } 
    else if (line.startsWith('> ')) {
      flushList();
      elements.push(<blockquote key={i} className="border-l-4 border-[#3c8ebd] pl-4 sm:pl-6 py-2 italic text-[#0b2636]/60 my-6 sm:my-8 bg-[#3c8ebd]/5 rounded-r-lg text-sm sm:text-base">{parseInline(line.substring(2))}</blockquote>);
    } 
    else if (line.trim() === '') {
      flushList();
    } 
    else {
      flushList();
      elements.push(<p key={i} className="mb-6 text-[#0b2636]/80 leading-relaxed text-base sm:text-lg">{parseInline(line)}</p>);
    }
  }
  flushList();
  return elements;
};

// --- COMPONENTS ---
const WriteupCard = ({ post, onClick }) => (
  <div 
    onClick={() => onClick(post)}
    className="group cursor-pointer border border-transparent border-b-slate-200/60 hover:border-[#3c8ebd] hover:shadow-lg py-6 sm:py-8 flex flex-col md:flex-row gap-4 md:gap-8 hover:bg-white transition-all px-4 sm:px-6 -mx-4 sm:-mx-6 rounded-xl"
  >
    <div className="md:w-40 shrink-0 flex flex-row md:flex-col gap-3 md:gap-2 items-center md:items-start pt-1">
      <span className="text-[#3c8ebd] font-black tracking-wider text-xs sm:text-sm">{post.date}</span>
      <span className="bg-[#0b2636] text-white text-[9px] sm:text-[10px] font-black tracking-widest px-2 sm:px-2.5 py-1 uppercase w-max">
        {post.category}
      </span>
    </div>
    
    <div className="flex-1 min-w-0">
      <h3 className="text-xl sm:text-2xl font-black text-[#0b2636] mb-2 sm:mb-3 group-hover:text-[#3c8ebd] transition-colors leading-tight break-words">
        {post.title}
      </h3>
      <p className="text-[#0b2636]/70 leading-relaxed text-sm sm:text-base line-clamp-2">
        {post.excerpt}
      </p>
    </div>
    
    <div className="shrink-0 flex items-center justify-between md:flex-col md:justify-center md:items-end gap-4 md:w-32 mt-2 md:mt-0">
      <span className="text-[10px] sm:text-xs font-bold text-[#0b2636]/50 tracking-widest uppercase flex items-center gap-1.5 min-w-0 max-w-full">
        <User className="w-3.5 h-3.5 shrink-0" /> <span className="truncate">{post.author}</span>
      </span>
      <div className="w-8 h-8 sm:w-10 sm:h-10 shrink-0 rounded-full border border-[#0b2636]/10 flex items-center justify-center group-hover:bg-[#3c8ebd] group-hover:border-[#3c8ebd] group-hover:text-white text-[#0b2636]/30 transition-all">
        <ArrowRight className="w-4 h-4 sm:w-5 sm:h-5 transform group-hover:translate-x-0.5 transition-transform" />
      </div>
    </div>
  </div>
);

const NavGrid = ({ navigate, currentPage, isSidebar }) => {
  const navItems = [
    { id: 'home', label: 'HOME' }, 
    { id: 'writeups', label: 'WRITEUPS' }, 
    { id: 'about', label: 'ABOUT' }, 
    { id: 'achievements', label: 'ACHIEVEMENTS' }, 
    { id: 'contact', label: 'CONTACT' }
  ];
  
  return (
    <div className={`grid ${isSidebar ? 'grid-cols-2 gap-x-8 gap-y-10 mt-6' : 'grid-cols-1 sm:grid-cols-2 gap-x-4 sm:gap-x-8 gap-y-8 sm:gap-y-10'}`}>
      {navItems.map(item => {
        const isActive = currentPage === item.id;
        
        if (isSidebar) {
          return (
            <button 
              key={item.id} 
              onClick={() => navigate(item.id)} 
              className={`text-left tracking-widest font-bold transition-colors w-full text-lg ${isActive ? 'text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.8)]' : 'text-white hover:text-white/80'}`}
            >
              <span className="drop-shadow-sm block">{item.label}</span>
            </button>
          );
        }

        return (
          <button 
            key={item.id} 
            onClick={() => navigate(item.id)} 
            className={`text-left tracking-[0.1em] min-[380px]:tracking-[0.15em] sm:tracking-[0.2em] font-medium text-[11px] min-[380px]:text-[13px] sm:text-[15px] md:text-[16px] transition-all flex items-center py-2 sm:py-0 ${isActive ? 'text-white' : 'text-white/70 hover:text-white'}`}
          >
            <span className="uppercase whitespace-nowrap">{item.label}</span>
          </button>
        );
      })}
    </div>
  )
}

const SubPageView = ({ bgText, title, sectionTitle, children }) => (
  <div className="w-full flex-grow bg-[#cbd6dc] flex flex-col font-sans">
    <div className="w-full h-32 sm:h-48 md:h-64 bg-gradient-to-r from-[#051017] via-[#0b1c26] to-[#051017] relative flex items-center justify-center overflow-hidden">
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none select-none opacity-[0.03]">
        <span className="text-5xl sm:text-6xl md:text-8xl lg:text-9xl font-serif italic text-white whitespace-nowrap tracking-widest px-4 text-center">
          {bgText || title}
        </span>
      </div>
      <h2 className="text-white text-lg sm:text-xl md:text-3xl tracking-[0.2em] md:tracking-[0.4em] font-light z-10 text-center px-4">{title}</h2>
    </div>
    
    <div className="w-full h-6 sm:h-8 md:h-10 bg-[#488ebf]"></div>

    <div className="w-full pl-4 sm:pl-6 md:pl-12 pr-[calc(1rem+80px)] md:pr-[calc(3rem+80px)] py-8 sm:py-16 flex-grow flex justify-center">
      <div className="bg-white w-full max-w-5xl relative p-6 sm:p-8 md:p-16 text-[#0b2636] shadow-sm min-h-[500px]">
        {sectionTitle && (
          <div className="absolute top-0 left-0 bg-[#488ebf] text-white px-4 sm:px-8 py-2 sm:py-3 text-xs sm:text-sm md:text-base font-bold tracking-widest z-10">
            {sectionTitle}
          </div>
        )}
        <div className="pt-8 sm:pt-10 w-full relative z-0">
          {children}
        </div>
      </div>
    </div>
  </div>
);

// --- VIEWS ---

const HomeView = ({ navigate, currentPage }) => (
  <div className="w-full flex flex-col">
    <div className="relative w-full min-h-[100svh] lg:h-[100svh] bg-[#0b1820] flex flex-col lg:flex-row overflow-y-auto lg:overflow-hidden group">
      
      <div className="flex w-full lg:w-[400px] xl:w-[450px] bg-[#0b1820] h-auto lg:h-full flex-col shadow-[10px_0_20px_rgba(0,0,0,0.5)] z-20 border-b lg:border-b-0 lg:border-r border-slate-800 relative shrink-0 pt-8 lg:pt-0">
        <div className="p-10 pt-10 lg:pt-16 relative">
          <div className="text-slate-700/20 absolute top-10 right-10 z-0 hidden lg:block">
            <Shield size={120} strokeWidth={1} />
          </div>
          <div className="relative z-10 select-none">
            <h1 className="text-5xl font-black italic tracking-widest text-[#2f4f66] opacity-30 leading-none">SYJC</h1>
            <h1 className="text-5xl font-black italic tracking-widest text-[#2f4f66] opacity-50 -mt-2 leading-none">TEAM!!!!!</h1>
            <h2 className="text-3xl font-bold italic text-[#3c8ebd] mt-2 tracking-wider">It's MyCTF!!!!!</h2>
          </div>
        </div>

        <div className="mb-14 mt-4 lg:mt-8 relative flex flex-col gap-2">
          <div className="bg-[#488ebf] text-white py-2 pl-10 pr-6 shadow-[0_4px_6px_rgba(0,0,0,0.3)] tracking-[0.2em] font-medium text-xs w-[90%] relative z-10">
            サイバーセキュリティチーム
          </div>
          <div className="bg-[#488ebf] text-white py-3 pl-10 pr-6 shadow-[0_4px_6px_rgba(0,0,0,0.3)] tracking-widest text-xl font-bold w-[105%] relative z-20">
            CAPTURE THE FLAG !!!!!
          </div>
          
          <div className="px-10 mt-10 w-full z-30 relative hidden lg:block">
            <NavGrid navigate={navigate} currentPage={currentPage} isSidebar={true} />
          </div>
        </div>
      </div>

      <div className="flex-1 relative h-[70vh] lg:h-full flex items-center justify-center overflow-hidden pl-4 pr-[calc(1rem+80px)] md:pr-[calc(1rem+80px)] lg:px-4">
        <div className="absolute inset-0 z-0 bg-[url('https://scontent-hkg1-2.cdninstagram.com/v/t51.82787-15/627934398_17862824781583144_676731908360055250_n.jpg?stp=dst-jpg_e35_tt6&_nc_cat=104&ig_cache_key=MzgyNjY3MjQ2NDczOTQyMzQ5Ng%3D%3D.3-ccb7-5&ccb=7-5&_nc_sid=58cdad&efg=eyJ2ZW5jb2RlX3RhZyI6InhwaWRzLjE0NDB4MTkyMC5zZHIuQzMifQ%3D%3D&_nc_ohc=Y1BvmLJPAVwQ7kNvwFnnKeU&_nc_oc=AdkR6-ZanVjDayw0txOgGUVUw96Dwk4d_un0TNEtsn7OIUDAiIGjYuXztGEpQT3iXkI&_nc_ad=z-m&_nc_cid=0&_nc_zt=23&_nc_ht=scontent-hkg1-2.cdninstagram.com&_nc_gid=EK-ck1zYkUX-kKcSvYQ7mQ&_nc_ss=8&oh=00_AfySCFf4aojj1-4320RgEyqEd4NmWhltzgyeueWG-XsmLQ&oe=69C03698')] bg-cover bg-center opacity-40 transition-transform duration-1000 group-hover:scale-105 mix-blend-luminosity"></div>
        <div className="absolute inset-0 z-0 bg-gradient-to-t lg:bg-gradient-to-l from-[#0b1820] via-[#0b1820]/60 to-[#0b1820]/80"></div>
        
        <div className="z-10 text-center flex flex-col items-center">
          <h1 className="text-white text-3xl sm:text-4xl md:text-6xl lg:text-7xl font-light tracking-[0.2em] md:tracking-[0.4em] leading-[1.5] drop-shadow-lg mb-4 sm:mb-6" style={{ fontFamily: 'serif' }}>
            <span className="block mb-2 sm:mb-4">ハッキングを</span>
            <span className="block">迷わない</span>
          </h1>
          <p className="text-white/80 tracking-[0.15em] sm:tracking-[0.3em] text-xs sm:text-sm md:text-base font-medium mt-4 sm:mt-6 drop-shadow-md uppercase px-2">
            Don't hesitate to hack.
          </p>
        </div>
        
        <div className="absolute bottom-6 sm:bottom-10 left-1/2 -translate-x-1/2 z-10 animate-bounce">
          <ChevronRight className="text-white/50 w-6 h-6 sm:w-8 sm:h-8 rotate-90" />
        </div>
      </div>
    </div>

    <div className="w-full bg-[#cbd6dc] flex flex-col relative z-20">
       <div className="w-full h-8 sm:h-10 bg-[#488ebf]"></div>
       <div className="w-full pl-4 sm:pl-6 md:pl-12 pr-[calc(1rem+80px)] md:pr-[calc(3rem+80px)] py-10 sm:py-16 flex justify-center">
          <div className="bg-white w-full max-w-5xl relative p-6 sm:p-8 md:p-16 text-[#0b2636] shadow-sm">
             <div className="absolute top-0 left-0 bg-[#488ebf] text-white px-4 sm:px-8 py-2 sm:py-3 text-xs sm:text-sm font-bold tracking-widest">
                LATEST UPDATES
             </div>
             <div className="pt-6 sm:pt-8 flex flex-col gap-6 font-medium">
                <div className="border-b border-slate-200 pb-4">
                  <span className="text-[#3c8ebd] text-xs sm:text-sm font-bold tracking-wider mb-1 sm:mb-2 block">2026.03.16</span>
                  <p className="text-base sm:text-lg">Welcome to the new SYJC Team official portal.</p>
                </div>
                <div className="border-b border-slate-200 pb-4">
                  <span className="text-[#3c8ebd] text-xs sm:text-sm font-bold tracking-wider mb-1 sm:mb-2 block">2026.02.06</span>
                  <p className="text-base sm:text-lg">Achieved 1st place at HKCERT 2025 Finals!</p>
                </div>
             </div>
          </div>
       </div>
    </div>
  </div>
);

const WriteupsView = ({ onPostClick, writeups = [], isLoading }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [selectedAuthor, setSelectedAuthor] = useState('ALL');

  const categories = ['ALL', ...new Set(writeups.map(w => w.category || 'Uncategorized'))];
  const authors = ['ALL', ...new Set(writeups.map(w => w.author || 'Anonymous'))];

  const filteredWriteups = writeups.filter(post => {
    const titleMatch = post.title?.toLowerCase().includes(searchQuery.toLowerCase()) || false;
    const excerptMatch = post.excerpt?.toLowerCase().includes(searchQuery.toLowerCase()) || false;
    const matchesSearch = titleMatch || excerptMatch;
    const matchesCategory = selectedCategory === 'ALL' || post.category === selectedCategory;
    const matchesAuthor = selectedAuthor === 'ALL' || post.author === selectedAuthor;
    
    return matchesSearch && matchesCategory && matchesAuthor;
  });

  return (
    <SubPageView bgText="Writeups & Docs" title="攻略・解説" sectionTitle="WRITEUPS">
      <div className="flex flex-col lg:flex-row gap-4 mb-8 sm:mb-10 pb-6 sm:pb-8 border-b border-[#0b2636]/10">
        <div className="flex-1 relative">
          <Search className="absolute left-3 sm:left-4 top-1/2 -translate-y-1/2 w-4 h-4 sm:w-5 sm:h-5 text-[#0b2636]/40" />
          <input 
            type="text" 
            placeholder="Search writeups..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 sm:pl-12 pr-4 py-2.5 sm:py-3 bg-white border-2 border-[#cbd6dc]/50 rounded-lg focus:outline-none focus:border-[#3c8ebd] focus:ring-4 focus:ring-[#3c8ebd]/10 transition-all text-sm sm:text-base text-[#0b2636] placeholder:text-[#0b2636]/40 font-medium"
          />
        </div>
        <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
          <select 
            value={selectedCategory} 
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="py-2.5 sm:py-3 px-3 sm:px-4 bg-white border-2 border-[#cbd6dc]/50 rounded-lg focus:outline-none focus:border-[#3c8ebd] focus:ring-4 focus:ring-[#3c8ebd]/10 transition-all text-sm sm:text-base text-[#0b2636] font-medium min-w-[140px] cursor-pointer"
          >
            {categories.map(c => <option key={c} value={c}>{c === 'ALL' ? 'All Categories' : c}</option>)}
          </select>
          <select 
            value={selectedAuthor} 
            onChange={(e) => setSelectedAuthor(e.target.value)}
            className="py-2.5 sm:py-3 px-3 sm:px-4 bg-white border-2 border-[#cbd6dc]/50 rounded-lg focus:outline-none focus:border-[#3c8ebd] focus:ring-4 focus:ring-[#3c8ebd]/10 transition-all text-sm sm:text-base text-[#0b2636] font-medium min-w-[140px] cursor-pointer"
          >
            {authors.map(a => <option key={a} value={a}>{a === 'ALL' ? 'All Authors' : a}</option>)}
          </select>
        </div>
      </div>
      
      {isLoading ? (
        <div className="py-12 sm:py-20 text-center text-[#0b2636]/50 px-4">
          <div className="animate-spin w-8 h-8 sm:w-10 sm:h-10 border-4 border-[#3c8ebd] border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-sm sm:text-base font-bold tracking-widest uppercase mt-4">Loading Writeups...</p>
        </div>
      ) : filteredWriteups.length > 0 ? (
        <div className="flex flex-col">
          {filteredWriteups.map((post, index) => <WriteupCard key={post.id || `${post.title}-${index}`} post={post} onClick={onPostClick} />)}
        </div>
      ) : (
        <div className="py-12 sm:py-20 text-center text-[#0b2636]/50 px-4">
          <div className="text-4xl sm:text-6xl mb-4">🔍</div>
          <h3 className="text-lg sm:text-xl font-bold mb-2">No writeups found</h3>
          <p className="text-sm sm:text-base">Try adjusting your search or filters.</p>
        </div>
      )}
    </SubPageView>
  );
};

const PostDetailView = ({ post, onBack }) => {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    window.scrollTo(0, 0);
    if (!post.url) {
      setContent("# Pending Publication\nThe detailed writeup for this challenge is currently being edited. Please check back later.");
      setLoading(false);
      return;
    }
    
    // Auto-convert standard github.com links to raw.githubusercontent.com format for fetch parsing
    let fetchUrl = post.url;
    if (fetchUrl.includes('github.com') && !fetchUrl.includes('raw.githubusercontent.com')) {
      fetchUrl = fetchUrl.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
    }

    setLoading(true);
    fetch(fetchUrl)
      .then(res => {
        if (!res.ok) throw new Error("Failed to fetch");
        return res.text();
      })
      .then(text => {
        setContent(text);
        setLoading(false);
      })
      .catch(err => {
        setContent("# Transmission Error\nFailed to fetch the writeup from the GitHub repository. Please verify your connection.");
        setLoading(false);
      });
  }, [post]);

  return (
    <SubPageView bgText="Reading Mode" title="WRITEUP" sectionTitle="ARTICLE">
      <div className="max-w-4xl mx-auto">
        <button 
          onClick={onBack}
          className="flex items-center gap-1.5 sm:gap-2 text-[#3c8ebd] font-bold tracking-widest text-xs sm:text-sm mb-8 sm:mb-12 hover:text-[#0b2636] transition-colors uppercase"
        >
          <ChevronLeft className="w-4 h-4 sm:w-5 sm:h-5" /> Back to List
        </button>
        
        <div className="mb-10 sm:mb-16 border-b-2 border-[#0b2636]/10 pb-6 sm:pb-8">
          <div className="flex items-center gap-3 sm:gap-4 mb-4 sm:mb-6">
            <span className="bg-[#3b8dbd] text-white px-2.5 sm:px-3 py-1 text-[9px] sm:text-[10px] font-black tracking-widest uppercase">{post.category}</span>
            <span className="text-[#0b2636]/40 font-bold text-[10px] sm:text-[11px] tracking-widest">{post.date}</span>
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black text-[#0b2636] tracking-tighter mb-4 sm:mb-6 leading-tight break-words">{post.title}</h1>
          <div className="flex items-center gap-2.5 sm:gap-3">
            <div className="w-6 h-6 sm:w-8 sm:h-8 rounded-full bg-[#0b2636] flex items-center justify-center text-white shrink-0">
              <User className="w-3 h-3 sm:w-4 sm:h-4" />
            </div>
            <span className="font-bold text-xs sm:text-sm tracking-widest text-[#0b2636]/70 uppercase truncate">{post.author}</span>
          </div>
        </div>

        <div className="prose-container overflow-hidden">
          {loading ? (
            <div className="animate-pulse space-y-4 sm:space-y-6">
              <div className="h-4 sm:h-6 bg-[#cbd6dc]/40 rounded w-3/4"></div>
              <div className="h-4 sm:h-6 bg-[#cbd6dc]/40 rounded w-full"></div>
              <div className="h-4 sm:h-6 bg-[#cbd6dc]/40 rounded w-5/6"></div>
              <div className="h-24 sm:h-32 bg-[#cbd6dc]/40 rounded w-full mt-6 sm:mt-8"></div>
            </div>
          ) : (
            parseMarkdown(content)
          )}
        </div>
      </div>
    </SubPageView>
  );
};

const AchievementsView = () => (
  <SubPageView bgText="Hall of Fame" title="実績・受賞" sectionTitle="ACHIEVEMENTS">
    <div className="space-y-8 sm:space-y-12">
      <div>
        <h3 className="text-xl sm:text-2xl font-bold mb-4 sm:mb-6 border-b-2 border-[#3c8ebd] inline-block pb-2">2026</h3>
        <ul className="space-y-3 sm:space-y-4">
          <li className="flex flex-col sm:flex-row gap-1 sm:gap-4 sm:items-center">
            <span className="text-[#3c8ebd] font-bold sm:w-32 shrink-0 text-sm sm:text-base">Secondary 2nd Place</span>
            <span className="text-base sm:text-lg">PolyU Nuttyshell CTF 2026</span>
          </li>
          <li className="flex flex-col sm:flex-row gap-1 sm:gap-4 sm:items-center">
            <span className="text-[#3c8ebd] font-bold sm:w-32 shrink-0 text-sm sm:text-base">Secondary 1st Place</span>
            <span className="text-base sm:text-lg">HKCERT CTF 2025 Final</span>
          </li>
        </ul>
      </div>
    </div>
  </SubPageView>
);

const AboutView = () => {
  const members = [
    { role: 'Leader', name: 'DXuwu' },
    { role: 'Deputy Leader', name: 'timo' },
    { role: 'Member', name: 'member3' },
    { role: 'Member', name: 'steve' },
    { role: 'Advisor', name: 'Albert' },
  ];

  return (
    <SubPageView bgText="Staff & Cast" title="チームメンバー" sectionTitle="MEMBER">
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-y-8 sm:gap-y-12 gap-x-6 sm:gap-x-8 mt-2 sm:mt-4">
        {members.map((m, idx) => (
          <div key={idx} className="flex flex-col">
            <span className="text-[#3c8ebd] text-[10px] sm:text-xs font-bold mb-1 sm:mb-2 tracking-widest">{m.role}</span>
            <span className="font-bold text-base sm:text-lg">{m.name}</span>
          </div>
        ))}
      </div>
    </SubPageView>
  );
};

const ContactView = () => (
  <SubPageView bgText="Get in Touch" title="お問い合わせ" sectionTitle="CONTACT">
    <div className="max-w-2xl text-base sm:text-lg space-y-6 sm:space-y-8">
      <p className="leading-relaxed">
        For inquiries regarding sponsorships, joint practices, or media relations, please reach out to our management team.
      </p>
      <div className="bg-[#cbd6dc]/30 p-6 sm:p-8">
        <div className="text-[#3c8ebd] text-[10px] sm:text-xs font-bold mb-1.5 sm:mb-2 tracking-widest">EMAIL</div>
        <div className="font-bold text-lg sm:text-xl break-words">syjc.hkjc.uk</div>
      </div>
      <div className="bg-[#cbd6dc]/30 p-6 sm:p-8">
        <div className="text-[#3c8ebd] text-[10px] sm:text-xs font-bold mb-1.5 sm:mb-2 tracking-widest">TWITTER / X</div>
        <div className="font-bold text-lg sm:text-xl break-words">@singyin_jockey_club</div>
      </div>
    </div>
  </SubPageView>
);

// --- MAIN APP COMPONENT ---
export default function App() {
  const [currentPage, setCurrentPage] = useState('home');
  const [activePost, setActivePost] = useState(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [writeups, setWriteups] = useState([]);
  const [isLoadingWriteups, setIsLoadingWriteups] = useState(true);

  useEffect(() => {
    setIsLoadingWriteups(true);
    // Fetch the writeup.json from the GitHub repo, using a cache-buster (?t=) to bypass GitHub's CDN cache
    fetch('https://raw.githubusercontent.com/dxinschool/SYJC/main/CTF/writeup.json?t=' + Date.now())
      .then(res => {
        if (!res.ok) throw new Error("Failed to fetch JSON");
        return res.json();
      })
      .then(data => {
        let parsedArray = [];
        if (Array.isArray(data)) {
          parsedArray = data;
        } else if (data && typeof data === 'object') {
          if (Array.isArray(data.writeups)) {
            parsedArray = data.writeups;
          } else {
            // Try to extract arrays if the JSON is structured by folders/categories
            Object.values(data).forEach(val => {
              if (Array.isArray(val)) parsedArray.push(...val);
            });
            // Fallback if it's a single flat object
            if (parsedArray.length === 0 && Object.keys(data).length > 0) {
              parsedArray = [data];
            }
          }
        }
        
        // Normalize JSON data so we guarantee the exact keys expected by our UI
        const normalizedData = parsedArray.map((post, index) => {
          // Construct the full raw GitHub URL using the relative path from the JSON
          const rawUrl = post.path 
            ? `https://raw.githubusercontent.com/dxinschool/SYJC/main/CTF/${post.path}`
            : (post.url || post.link || '');

          return {
            ...post,
            id: post.id || `writeup-${index}`,
            title: post.challenge || post.title || post.name || 'Untitled Writeup',
            category: post.category || post.type || 'CTF',
            author: post.author || post.writer || 'SYJC Team',
            excerpt: post.notes || post.excerpt || post.description || 'No summary available.',
            date: post.solved_date || post.date || post.time || new Date().getFullYear().toString(),
            url: rawUrl
          };
        });
        
        setWriteups(normalizedData);
        setIsLoadingWriteups(false);
      })
      .catch(err => {
        console.error("Failed to load writeups:", err);
        setWriteups([]);
        setIsLoadingWriteups(false);
      });
  }, []);

  const handleNavigate = (page) => {
    setCurrentPage(page);
    setActivePost(null);
    setIsMenuOpen(false);
    window.scrollTo(0, 0);
  };

  return (
    <div className="flex w-full min-h-screen bg-[#0b1820] font-sans selection:bg-[#3c8ebd] selection:text-white overflow-x-hidden">
      
      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col min-h-screen relative w-full">
        <div className="flex-1 w-full flex flex-col">
          {currentPage === 'home' && <HomeView navigate={handleNavigate} currentPage={currentPage} />}
          {currentPage === 'writeups' && !activePost && <WriteupsView onPostClick={setActivePost} writeups={writeups} isLoading={isLoadingWriteups} />}
          {currentPage === 'writeups' && activePost && <PostDetailView post={activePost} onBack={() => setActivePost(null)} />}
          {currentPage === 'achievements' && <AchievementsView />}
          {currentPage === 'about' && <AboutView />}
          {currentPage === 'contact' && <ContactView />}
        </div>

        {/* FOOTER */}
        <footer className="bg-[#0b1820] text-white py-10 sm:py-12 px-6 sm:px-8 w-full border-t-[6px] sm:border-t-[8px] border-[#3c8ebd] z-30 pr-[calc(1.5rem+80px)] md:pr-[calc(2rem+80px)]">
          <div className="max-w-5xl mx-auto flex flex-col md:flex-row justify-between items-center space-y-6 md:space-y-0">
            <div className="flex flex-col text-center md:text-left">
              <h2 className="text-2xl sm:text-3xl md:text-4xl font-black italic tracking-widest text-[#3c8ebd]">SYJC TEAM!!!!!</h2>
              <h3 className="text-base sm:text-lg md:text-xl font-bold italic text-white mt-1">It's MyCTF!!!!!</h3>
            </div>
            
            <div className="flex flex-wrap justify-center gap-4 sm:gap-6 md:gap-8 text-xs sm:text-sm font-bold tracking-widest text-slate-300 items-center">
              <button onClick={() => handleNavigate('home')} className={`transition-colors py-1 ${currentPage === 'home' ? 'text-white' : 'hover:text-white'}`}>
                {currentPage === 'home' ? '➤ HOME' : 'HOME'}
              </button>
              <button onClick={() => handleNavigate('writeups')} className={`transition-colors py-1 ${currentPage === 'writeups' ? 'text-white' : 'hover:text-white'}`}>
                {currentPage === 'writeups' ? '➤ WRITEUPS' : 'WRITEUPS'}
              </button>
              <button onClick={() => handleNavigate('about')} className={`transition-colors py-1 ${currentPage === 'about' ? 'text-white' : 'hover:text-white'}`}>
                {currentPage === 'about' ? '➤ ABOUT' : 'ABOUT'}
              </button>
              <button onClick={() => handleNavigate('contact')} className={`transition-colors py-1 ${currentPage === 'contact' ? 'text-white' : 'hover:text-white'}`}>
                {currentPage === 'contact' ? '➤ CONTACT' : 'CONTACT'}
              </button>
              
              <div className="w-px h-4 bg-slate-700/50 hidden sm:block mx-1"></div>
              
              <a 
                href="https://www.instagram.com/singyin_jockey_club/" 
                target="_blank" 
                rel="noopener noreferrer" 
                className="text-slate-400 hover:text-white transition-colors p-1"
                aria-label="Instagram"
              >
                <Instagram className="w-5 h-5 sm:w-6 sm:h-6" />
              </a>
            </div>
          </div>
          <div className="max-w-5xl mx-auto mt-8 sm:mt-10 pt-4 sm:pt-6 border-t border-slate-700/30 text-[10px] sm:text-xs text-slate-500 font-mono text-center">
            © {new Date().getFullYear()} SYJC TEAM! All rights reserved.
          </div>
        </footer>
      </div>

      {/* --- GLOBAL MENU TRIGGER / CLOSE BUTTON --- */}
      <div 
        className={`fixed top-0 right-0 z-[100] bg-[#3388bb] cursor-pointer transition-all duration-200 flex flex-col items-center pt-[32px] hover:bg-[#2d76a3] ${isMenuOpen ? '' : 'shadow-[-4px_0_15px_rgba(0,0,0,0.3)]'}`} 
        style={{ width: '80px', height: '160px' }}
        onClick={() => setIsMenuOpen(!isMenuOpen)}
      >
        <div className="relative w-6 h-6 mb-8 flex items-center justify-center">
          <div className={`absolute w-full h-[2px] bg-white transition-all duration-300 ${isMenuOpen ? 'rotate-45' : '-translate-y-[6px]'}`}></div>
          <div className={`absolute w-full h-[2px] bg-white transition-all duration-300 ${isMenuOpen ? 'opacity-0' : 'opacity-100'}`}></div>
          <div className={`absolute w-full h-[2px] bg-white transition-all duration-300 ${isMenuOpen ? '-rotate-45' : 'translate-y-[6px]'}`}></div>
        </div>
        <div className="relative h-20 w-full flex justify-center">
           <span className={`absolute text-white text-[13px] font-black tracking-[0.4em] leading-none uppercase select-none transition-opacity duration-300 ${isMenuOpen ? 'opacity-100' : 'opacity-0'}`} style={{ writingMode: 'vertical-rl', transform: 'scaleY(1.25)' }}>CLOSE</span>
           <span className={`absolute text-white text-[13px] font-black tracking-[0.4em] leading-none uppercase select-none transition-opacity duration-300 ${isMenuOpen ? 'opacity-0' : 'opacity-100'}`} style={{ writingMode: 'vertical-rl', transform: 'scaleY(1.25)' }}>MENU</span>
        </div>
      </div>

      {/* --- RESPONSIVE OVERLAY MENU --- */}
      <div className={`fixed inset-0 z-[90] transition-opacity duration-300 ${isMenuOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'}`}>
        <div className="absolute inset-0 bg-black/70 backdrop-blur-[6px]" onClick={() => setIsMenuOpen(false)}></div>
        
        {/* Panel matching the menu button color */}
        <div className={`absolute right-0 top-0 bottom-0 w-[85%] sm:w-[70%] max-w-[460px] bg-[#3388bb] transform transition-transform duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] flex flex-col shadow-[-10px_0_30px_rgba(0,0,0,0.5)] ${isMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
          
          {/* Menu Links with right padding to avoid the blue bar */}
          <div className="flex-1 pl-8 sm:pl-12 md:pl-16 pr-8 sm:pr-[calc(2rem+80px)] md:pr-[calc(4rem+80px)] flex flex-col justify-center mt-[160px] sm:mt-0">
             <div className="space-y-12 sm:space-y-16">
                <div>
                  <h4 className="text-white/80 text-[10px] sm:text-[11px] font-black tracking-[0.4em] mb-8 sm:mb-10 uppercase border-b border-white/30 pb-4">Navigation</h4>
                  <NavGrid navigate={handleNavigate} currentPage={currentPage} isSidebar={false} />
                </div>
                
                <div>
                  <h4 className="text-white/80 text-[10px] sm:text-[11px] font-black tracking-[0.4em] mb-6 uppercase border-b border-white/30 pb-4">Socials</h4>
                  <a 
                    href="https://www.instagram.com/singyin_jockey_club/" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-3 text-white/70 hover:text-white transition-colors"
                  >
                    <Instagram className="w-5 h-5 sm:w-6 sm:h-6" />
                    <span className="tracking-[0.15em] font-medium text-[11px] sm:text-[13px] uppercase">Instagram</span>
                  </a>
                </div>
             </div>
          </div>

        </div>
      </div>

    </div>
  );
}